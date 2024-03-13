#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
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

const static std::string_view date_format{"{:%Y-%m-%dT%H:%M:%S.000Z}"};

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
		logging::debug("{}: returned {}", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	auto conn = irods::get_connection(*irods_username);
	auto rcComm_t_ptr = static_cast<RcComm*>(conn);

	irods::experimental::filesystem::path bucket_base;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		bucket_base = bucket.value();
	}
	else {
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned {}", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	auto base_length = bucket_base.string().size();
	auto resolved_path = irods::s3::finish_path(bucket_base, url.segments());
	boost::property_tree::ptree document;

	irods::experimental::filesystem::path the_prefix;
	if (const auto prefix = url.params().find("prefix"); prefix != url.params().end()) {
		the_prefix = (*prefix).value;
	}

	// For recursive searches, no delimiter is passed in.  In that case only return all data objects
	// which have the prefix.
	// TODO:  We might not be able to support delimiters that are not "/".
	bool delimiter_in_request = false;
	if (const auto prefix = url.params().find("delimiter"); prefix != url.params().end()) {
		delimiter_in_request = true;
	}

	auto full_path = resolved_path / the_prefix;

	std::string query;

	document.add("ListBucketResult", "");
	document.add("ListBucketResult.Name", bucket_base.c_str());
	document.add("ListBucketResult.Prefix", the_prefix.c_str());
	document.add("ListBucketResult.Marker", "");
	document.add("ListBucketResult.IsTruncated", "false");

	if (delimiter_in_request) {
		if (full_path.object_name().empty()) {
			// Path ends in a slash, this is an exact collection match
			// and all objects in that collection

			// Get exact collections underneath this collection
			query = fmt::format(
				"select COLL_NAME where COLL_NAME like '{}/%' and COLL_NAME not like '{}/%/%'",
				full_path.parent_path().c_str(),
				full_path.parent_path().c_str());
			logging::debug("{}: query={}", __FUNCTION__, query);
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "");
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				key += "/";
				object.put("Prefix", key);
				document.add_child("ListBucketResult.CommonPrefixes", object);
			}

			// Get the data objects within the collection
			query = fmt::format(
				"select COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME where COLL_NAME = '{}'",
				full_path.parent_path().c_str());
			logging::debug("{}: query={}", __FUNCTION__, query);
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "") + "/" + row[1];
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				object.put("Key", key);
				object.put("Etag", row[0] + row[1]);
				object.put("Owner", row[2]);
				object.put("Size", atoi(row[3].c_str()));
				try {
					std::time_t modified_epoch_time = boost::lexical_cast<std::time_t>(row[4]);
					std::string modified_time_str =
						irods::s3::api::common_routines::convert_time_t_to_str(modified_epoch_time, date_format);
					object.put("LastModified", modified_time_str);
				}
				catch (const boost::bad_lexical_cast&) {
					// do nothing - don't add LastModified tag
				}
				document.add_child("ListBucketResult.Contents", object);
			}
		}
		else {
			// Path does not end in a slash.  This is a query for collections and data objects
			// with a trailing wildcard.

			// First get collections
			query = fmt::format(
				"select COLL_NAME where COLL_NAME like '{}%' and COLL_NAME not like '{}%/%'",
				full_path.c_str(),
				full_path.c_str());
			logging::debug("{}: query={}", __FUNCTION__, query);
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "");
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				key += "/";
				object.put("Prefix", key);
				document.add_child("ListBucketResult.CommonPrefixes", object);
			}

			// Now get data objects
			query = fmt::format(
				"select COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME where COLL_NAME = '{}'"
				" and DATA_NAME like '{}%'",
				full_path.parent_path().c_str(),
				full_path.object_name().c_str());
			logging::debug("{}: query={}", __FUNCTION__, query);
			for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
				ptree object;
				std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "") + "/" + row[1];
				if (key.starts_with("/")) {
					key = key.substr(1);
				}
				object.put("Key", key);
				object.put("Etag", row[0] + row[1]);
				object.put("Owner", row[2]);
				object.put("Size", atoi(row[3].c_str()));
				try {
					std::time_t modified_epoch_time = boost::lexical_cast<std::time_t>(row[4]);
					std::string modified_time_str =
						irods::s3::api::common_routines::convert_time_t_to_str(modified_epoch_time, date_format);
					object.put("LastModified", modified_time_str);
				}
				catch (const boost::bad_lexical_cast&) {
					// do nothing - don't add LastModified tag
				}
				document.add_child("ListBucketResult.Contents", object);
			}
		}
	}
	else {
		// No delimiter in request.  When there is no delimiter provided, for listing purposes AWS simply searches for
		// all objects with the given prefix.  To make this behave similarly in iRODS, we need to perform two searches:
		//
		// 1.  Look for objects with COLL_NAME like <prefix>%
		// 2.  Look for objects with COLL_NAME = <parent> and DATA_NAME like <object>%

		// look for objects with COLL_NAME like <prefix>%
		query = fmt::format(
			"select COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME where COLL_NAME like '{}%'",
			full_path.c_str());
		logging::debug("{}: query={}", __FUNCTION__, query);
		for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
			ptree object;
			std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "") + "/" + row[1];
			if (key.starts_with("/")) {
				key = key.substr(1);
			}
			object.put("Key", key);
			object.put("Etag", row[0] + row[1]);
			object.put("Owner", row[2]);
			object.put("Size", atoi(row[3].c_str()));
			try {
				std::time_t modified_epoch_time = boost::lexical_cast<std::time_t>(row[4]);
				std::string modified_time_str =
					irods::s3::api::common_routines::convert_time_t_to_str(modified_epoch_time, date_format);
				object.put("LastModified", modified_time_str);
			}
			catch (const boost::bad_lexical_cast&) {
				// do nothing - don't add LastModified tag
			}
			document.add_child("ListBucketResult.Contents", object);
		}

		// look for objects with COLL_NAME = <parent> and DATA_NAME like <object>%
		query = fmt::format(
			"select COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME where COLL_NAME = '{}'"
			" and DATA_NAME like '{}%'",
			full_path.parent_path().c_str(),
			full_path.object_name().c_str());
		logging::debug("{}: query={}", __FUNCTION__, query);
		for (auto&& row : irods::query<RcComm>(rcComm_t_ptr, query)) {
			ptree object;
			std::string key = (row[0].size() > base_length ? row[0].substr(base_length) : "") + "/" + row[1];
			if (key.starts_with("/")) {
				key = key.substr(1);
			}
			object.put("Key", key);
			object.put("Etag", row[0] + row[1]);
			object.put("Owner", row[2]);
			object.put("Size", atoi(row[3].c_str()));
			try {
				std::time_t modified_epoch_time = boost::lexical_cast<std::time_t>(row[4]);
				std::string modified_time_str =
					irods::s3::api::common_routines::convert_time_t_to_str(modified_epoch_time, date_format);
				object.put("LastModified", modified_time_str);
			}
			catch (const boost::bad_lexical_cast&) {
				// do nothing - don't add LastModified tag
			}
			document.add_child("ListBucketResult.Contents", object);
		}
	}

	beast::http::response<beast::http::string_body> string_body_response(std::move(response));
	std::stringstream s;
	boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
	settings.indent_char = ' ';
	settings.indent_count = 4;
	boost::property_tree::write_xml(s, document, settings);
	string_body_response.body() = s.str();

	logging::debug("{}: response body {}", __FUNCTION__, s.str());
	logging::debug("{}: returned {}", __FUNCTION__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
}
