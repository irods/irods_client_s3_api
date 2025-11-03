#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/beast.hpp>
#include <boost/dll.hpp>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/url.hpp>
#include <boost/lexical_cast.hpp>

#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/query_builder.hpp>

#include <iostream>
#include <unordered_set>
#include <chrono>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace logging = irods::http::logging;

static const std::string date_format{"{:%Y-%m-%dT%H:%M:%S+00:00}"};

void irods::s3::actions::handle_listbuckets(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
	const boost::urls::url_view& url)
{
	using namespace boost::property_tree;

	beast::http::response<beast::http::empty_body> response;

	auto irods_username = irods::s3::authentication::authenticates(parser, url);

	if (!irods_username) {
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	auto conn = irods::get_connection(*irods_username);
	auto rcComm_t_ptr = static_cast<RcComm*>(conn);

	boost::property_tree::ptree document;
	document.add("ListAllMyBucketsResult", "");
	document.add("ListAllMyBucketsResult.Buckets", "");

	// get the buckets from the configuration
	auto& bucket_mapping = irods::http::globals::bucket_mapping_library();

	using T = decltype(bucket_mapping_list);
	auto bm_list = bucket_mapping.get<T>("bucket_mapping_list");
	bucket_mapping_entry* buckets{};
	std::size_t bucket_size{};
	if (bm_list(&buckets, &bucket_size) != 0) {
		response.result(beast::http::status::internal_server_error);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	irods::at_scope_exit free_buckets{[&bucket_mapping, &buckets, bucket_size] {
		using T = decltype(bucket_mapping_free);
		auto bm_free = bucket_mapping.get<T>("bucket_mapping_free");
		for (std::size_t i = 0; i < bucket_size; ++i) {
			bm_free(buckets[i].bucket);
			bm_free(buckets[i].collection);
		}
		bm_free(buckets);
		buckets = nullptr;
	}};

	logging::debug("{}: number of mapped buckets = [{}]", __func__, bucket_size);

	std::vector<const char*> collections;
	collections.reserve(128); // Reduces need to resize/re-allocate memory for small bucket mappings.
	for (std::size_t i = 0; i < bucket_size; ++i) {
		collections.push_back(buckets[i].collection);
	}
	const auto in_args = fmt::format("'{}'", fmt::join(collections, "', '"));

	const auto query = fmt::format("select COLL_NAME, COLL_CREATE_TIME where COLL_NAME in ({})", in_args);
	logging::debug("{}: query = [{}]", __func__, query);

	for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
		const auto ctime = boost::lexical_cast<std::time_t>(row[1]);
		ptree object;
		object.put("CreationDate", irods::s3::api::common_routines::convert_time_t_to_str(ctime, date_format));

		const auto iter = std::find_if(
			buckets, buckets + bucket_size, [&c = row[0]](const bucket_mapping_entry& e) { return c == e.collection; });
		if (iter == buckets + bucket_size) {
			logging::warn("{}: Cannot resolve collection [{}] to bucket name. Skipping mapping.", __func__, row[0]);
			continue;
		}
		object.put("Name", iter->bucket);

		document.add_child("ListAllMyBucketsResult.Buckets.Bucket", object);
	}
	document.add("ListAllMyBucketsResult.Owner", "");

	// convert empty_body response to string_body
	beast::http::response<beast::http::string_body> string_body_response(std::move(response));

	std::stringstream s;
	boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
	settings.indent_char = ' ';
	settings.indent_count = 4;
	boost::property_tree::write_xml(s, document, settings);
	string_body_response.body() = s.str();
	logging::debug("{}: return string:\n{}", __func__, s.str());
	logging::debug("{}: returned [{}]", __func__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
	return;
}
