#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/globals.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <experimental/coroutine>
#include <boost/beast.hpp>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/url.hpp>
#include <boost/lexical_cast.hpp>

#include <irods/filesystem.hpp>
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
		logging::debug("{}: returned {}", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	auto conn = irods::get_connection(*irods_username);
	auto rcComm_t_ptr = static_cast<RcComm*>(conn);

	boost::property_tree::ptree document;
	document.add("ListAllMyBucketsResult", "");
	document.add("ListAllMyBucketsResult.Buckets", "");

	// get the buckets from the configuration
	const nlohmann::json& config = irods::http::globals::configuration();
	const auto bucket_list =
		config.at(nlohmann::json::json_pointer{"/s3_server/plugins/static_bucket_resolver/mappings"});
	for (const auto& [bucket, collection] : bucket_list.items()) {
		// Get the creation time for the collection
		bool found = false;
		std::string query;
		std::time_t create_collection_epoch_time = 0;

		query = fmt::format("select COLL_CREATE_TIME where COLL_NAME = '{}'", collection.get_ref<const std::string&>());

		logging::debug("{}: query = {}", __FUNCTION__, query);

		for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
			found = true;
			create_collection_epoch_time = boost::lexical_cast<std::time_t>(row[0]);
			break;
		}

		// If creation time not found, user does not have access to the collection the bucket
		// maps to.  Do not add this bucket to the list.
		if (found) {
			std::string create_collection_epoch_time_str =
				irods::s3::api::common_routines::convert_time_t_to_str(create_collection_epoch_time, date_format);

			ptree object;
			object.put("CreationDate", create_collection_epoch_time_str);
			object.put("Name", bucket);
			document.add_child("ListAllMyBucketsResult.Buckets.Bucket", object);
		}
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
	logging::debug("{}: return string:\n{}", __FUNCTION__, s.str());
	logging::debug("{}: returned {}", __FUNCTION__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
	return;
}
