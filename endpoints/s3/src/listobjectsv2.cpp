#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/listobjects.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/session.hpp"

#include <irods/filesystem.hpp>
#include <irods/query_builder.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/beast.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/url.hpp>

#include <fmt/format.h>

#include <chrono>
#include <iostream>
#include <unordered_set>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace logging = irods::http::logging;
namespace fs = irods::experimental::filesystem;

using data_object_info_map_type = irods::s3::detail::data_object_info_map_type;

void irods::s3::actions::handle_listobjects_v2(
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
	if (nullptr == rcComm_t_ptr) {
		response.result(beast::http::status::internal_server_error);
		logging::error("{}: RcComm is nullptr", __func__);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	irods::experimental::filesystem::path bucket_base;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		logging::debug("{}: bucket = [{}]", __func__, bucket.value().c_str());
		bucket_base = bucket.value();
	}
	else {
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	auto resolved_path = irods::s3::finish_path(bucket_base, url.segments());
	boost::property_tree::ptree document;

	irods::experimental::filesystem::path the_prefix;
	if (const auto prefix = url.params().find("prefix"); prefix != url.params().end()) {
		the_prefix = (*prefix).value;
	}

	auto full_path = resolved_path / the_prefix;

	std::string query;

	document.add("ListBucketResult", "");
	document.add("ListBucketResult.Name", (*url.segments().begin()).c_str());
	document.add("ListBucketResult.Prefix", the_prefix.c_str());
	document.add("ListBucketResult.Marker", "");
	document.add("ListBucketResult.IsTruncated", "false");

	bool url_encode_keys = false;
	if (const auto encoding_type = url.params().find("encoding-type"); encoding_type != url.params().end()) {
		url_encode_keys = (*encoding_type).value == "url";
		document.add("ListBucketResult.EncodingType", (*encoding_type).value);
	}

	const auto bucket_base_str = std::string_view{bucket_base.c_str()};

	// Need to use a query here because fs::client::collection_iterator does not return all replica information.
	data_object_info_map_type id_to_info;

	// For recursive searches, no delimiter is passed in.  In that case only return all data objects
	// which have the prefix.
	// TODO(#221):  We might not be able to support delimiters that are not "/".
	if (const auto delimiter = url.params().find("delimiter"); delimiter != url.params().end()) {
		document.add("ListBucketResult.Delimiter", (*delimiter).value);
		const auto parent_path_str = full_path.parent_path().string();
		if (full_path.object_name().empty()) {
			// Get exact collections underneath this collection
			query = fmt::format("select COLL_NAME where COLL_PARENT_NAME = '{}'", full_path.parent_path().c_str());
			logging::debug("{}: query=[{}]", __func__, query);
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				std::string key = (row[0].size() > bucket_base_str.size() ? row[0].substr(bucket_base_str.size()) : "");
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				key += "/"; // append trailing slash to show that this is a folder
				object.put("Prefix", key);
				document.add_child("ListBucketResult.CommonPrefixes", object);
			}

			query = fmt::format(
				"select DATA_ID, COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME, DATA_REPL_STATUS, "
				"order(DATA_REPL_NUM) "
				"where COLL_NAME = '{}'",
				full_path.parent_path().c_str());
			detail::get_data_object_info_with_query(*rcComm_t_ptr, query, id_to_info);
			detail::add_data_object_info_to_ListBucketResult_Contents(
				id_to_info, bucket_base, url_encode_keys, document);
		}
		else {
			// Path does not end in a slash. This is a query for collections and data objects with a trailing wildcard.

			// Get the collections which match first...
			query = fmt::format(
				"select COLL_NAME where COLL_NAME like '{}%' and COLL_NAME not like '{}%/%'",
				full_path.c_str(),
				full_path.c_str());
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				const auto entry_path = fs::path{row[0]};
				std::string key =
					(parent_path_str.size() > bucket_base_str.size() ? parent_path_str.substr(bucket_base_str.size())
				                                                     : "") +
					"/" + entry_path.object_name().c_str();
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				key += "/"; // append trailing slash to show that this is a folder
				object.put("Prefix", key);
				document.add_child("ListBucketResult.CommonPrefixes", object);
			}

			query = fmt::format(
				"select DATA_ID, COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME, DATA_REPL_STATUS, "
				"order(DATA_REPL_NUM) "
				"where COLL_NAME = '{}' and DATA_NAME like '{}%'",
				full_path.parent_path().c_str(),
				full_path.object_name().c_str());
			detail::get_data_object_info_with_query(*rcComm_t_ptr, query, id_to_info);
			detail::add_data_object_info_to_ListBucketResult_Contents(
				id_to_info, bucket_base, url_encode_keys, document);
		}
	}
	else {
		logging::debug("{}: no delimiter in request", __func__);

		// No delimiter in request.  When there is no delimiter provided, for listing purposes AWS simply searches for
		// all objects with the given prefix.  To make this behave similarly in iRODS, we need to perform two searches:
		//
		// 1.  Look for objects with COLL_NAME like <prefix>%
		// 2.  Look for objects with COLL_NAME = <parent> and DATA_NAME like <object>%

		// look for objects with COLL_NAME like <prefix>%
		query = fmt::format(
			"select DATA_ID, COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME, DATA_REPL_STATUS, "
			"order(DATA_REPL_NUM) "
			"where COLL_NAME like '{}%'",
			full_path.c_str());
		detail::get_data_object_info_with_query(*rcComm_t_ptr, query, id_to_info);

		// look for objects with COLL_NAME = <parent> and DATA_NAME like <object>%
		query = fmt::format(
			"select DATA_ID, COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME, DATA_REPL_STATUS, "
			"order(DATA_REPL_NUM) "
			"where COLL_NAME = '{}' and DATA_NAME like '{}%'",
			full_path.parent_path().c_str(),
			full_path.object_name().c_str());
		detail::get_data_object_info_with_query(*rcComm_t_ptr, query, id_to_info);

		detail::add_data_object_info_to_ListBucketResult_Contents(id_to_info, bucket_base, url_encode_keys, document);
	}

	beast::http::response<beast::http::string_body> string_body_response(std::move(response));
	std::stringstream s;
	boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
	settings.indent_char = ' ';
	settings.indent_count = 4;
	boost::property_tree::write_xml(s, document, settings);
	string_body_response.body() = s.str();

	logging::debug("{}: response body {}", __func__, s.str());
	logging::debug("{}: returned [{}]", __func__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
}
