#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

#include <irods/filesystem.hpp>

#include <irods/filesystem/collection_entry.hpp>
#include <irods/filesystem/collection_iterator.hpp>
#include <irods/filesystem/filesystem.hpp>
#include <irods/filesystem/filesystem_error.hpp>
#include <irods/filesystem/path.hpp>
#include <irods/genQuery.h>
#include <irods/irods_exception.hpp>
#include <irods/msParam.h>
#include <irods/rcConnect.h>
#include <irods/rodsClient.h>
#include <irods/irods_client_api_table.hpp>
#include <irods/irods_pack_table.hpp>
#include <irods/irods_parse_command_line_options.hpp>
#include <irods/filesystem.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsGenQuery.h>
#include <irods/rodsPath.h>
#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>
#include <irods/irods_query.hpp>
#include <irods/query_builder.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/stacktrace.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <sstream>
#include <map>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

void irods::s3::actions::handle_deleteobjects(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& empty_body_parser,
	const boost::urls::url_view& url)
{
	beast::http::response<beast::http::string_body> response;

	// Permission verification stuff should go roughly here.

	auto irods_username = irods::s3::authentication::authenticates(empty_body_parser, url);
	if (!irods_username) {
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// change the parser to a string_body parser and read the body
	empty_body_parser.eager(true);
	beast::http::request_parser<boost::beast::http::string_body> parser{std::move(empty_body_parser)};
	beast::http::read(session_ptr->stream().socket(), session_ptr->get_buffer(), parser);

	// Reconnect to the iRODS server as the target user.
	// The rodsadmin account from the config file will act as the proxy for the user.
	auto conn = irods::get_connection(*irods_username);

	fs::path path;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		path = bucket.value();
	}
	else {
		response.result(beast::http::status::not_found);
		logging::debug("{}: Could not find bucket", __func__);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// read and parse the body
	std::string& request_body = parser.get().body();

	logging::debug("{}: request_body:\n{}", __func__, request_body);
	boost::property_tree::ptree request_body_property_tree;
	try {
		std::stringstream ss;
		ss << request_body;
		boost::property_tree::read_xml(ss, request_body_property_tree);
	}
	catch (boost::property_tree::xml_parser_error& e) {
		logging::debug("{}: Could not parse XML body.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	catch (...) {
		logging::debug("{}: Unknown error parsing XML body.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	bool quiet_flag = true;

	// build a map to hold the key and a string indicating success or failure with reason
	std::map<std::string, std::string> key_map;
	try {
		for (boost::property_tree::ptree::value_type& v : request_body_property_tree.get_child("Delete")) {
			const std::string& tag = v.first;
			if (tag == "Quiet") {
				quiet_flag = v.second.get_value<bool>();
				logging::debug("{}: quiet tag value={}", __func__, v.second.data());
				continue;
			}
			else if (tag == "Object") {
				const boost::property_tree::ptree& v2 = v.second;
				std::string key = path.string() + "/" + v2.get<std::string>("Key");
				key_map[key] = "";
			}
		}
	}
	catch (...) {
		logging::debug("{}: Error parsing XML body.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	logging::debug("{}: quiet_flag={}", __func__, quiet_flag);
	for (const auto& [key, value] : key_map) {
		logging::debug("{}: key={}", __func__, key);
		try {
			// Delete collections after all objects have been deleted.
			if (key.back() == '/') {
				logging::debug("{}: Skipping collection [{}]", __func__, key);
				continue;
			}

			if (!fs::client::exists(conn, key)) {
				logging::debug("{}: Could not find {}", __func__, key);
				key_map[key] = "NoSuchKey";
				continue;
			}

			if (fs::client::remove(conn, key, experimental::filesystem::remove_options::no_trash)) {
				logging::debug("{}: Remove {} (object) successful", __func__, key);
				key_map[key] = "Success";
			}
			else {
				logging::debug("{}: Deletion of key {} (object) failed", __func__, key);
				key_map[key] = "InternalError";
			}
		}
		catch (const irods::exception& e) {
			beast::http::response<beast::http::empty_body> response;
			logging::debug("{}: Exception encountered", __func__);

			switch (e.code()) {
				case USER_ACCESS_DENIED:
				case CAT_NO_ACCESS_PERMISSION:
					logging::debug("{}: No access to delete key {}", __func__, key);
					key_map[key] = "AccessDenied";
					break;
				default:
					logging::debug("{}: Unknown exception when deleting key {}", __func__, key);
					key_map[key] = "InternalError";
					break;
			}
		}
	}

	logging::debug("{}: Deleting empty collections now.", __func__);
	for (const auto& [key, value] : key_map) {
		logging::debug("{}: key={}", __func__, key);

		// Any keys with a non-empty value means it has already been processed. Skip it to ensure that we are only
		// dealing with prefixes.
		if (!value.empty()) {
			logging::debug("{}: skipping key [{}] because it was already processed.", __func__, key);
			continue;
		}

		try {
			if (!fs::client::exists(conn, key)) {
				logging::debug("{}: Could not find {}", __func__, key);
				key_map[key] = "NoSuchKey";
				continue;
			}

			// Remove trailing slash - it confuses remove_all. Use remove_all here because some S3 clients only include
			// the base prefix in the request instead of all common prefixes.
			const auto key_without_trailing_slash = key.substr(0, key.size() - 1);
			if (fs::client::remove_all(conn, key_without_trailing_slash, fs::remove_options::no_trash) >= 0) {
				logging::debug("{}: Remove {} (collection) successful", __func__, key);
				key_map[key] = "Success";
			}
			else {
				logging::debug("{}: Deletion of key {} (collection) failed", __func__, key);
				key_map[key] = "InternalError";
			}
		}
		catch (const irods::exception& e) {
			beast::http::response<beast::http::empty_body> response;
			logging::debug("{}: Exception encountered", __func__);

			switch (e.code()) {
				case USER_ACCESS_DENIED:
				case CAT_NO_ACCESS_PERMISSION:
					logging::debug("{}: No access to delete key {}", __func__, key);
					key_map[key] = "AccessDenied";
					break;
				default:
					logging::debug("{}: Unknown exception when deleting key {}", __func__, key);
					key_map[key] = "InternalError";
					break;
			}
		}
	}

	// Now send the response
	// Example response:
	// <DeleteResult>
	//     <Deleted>
	//         <Key>key1</Key>
	//     </Deleted>
	//     <Deleted>
	//         <Key>key2</Key>
	//     <Deleted>
	//     <Error>
	//         <Key>key3</Key>
	//         <Code>AccessDenied</Code>
	//         <Message>Access Denied</Message>
	//     </Error>
	//     <Error>
	//         <Key>key4</Key>
	//         <Code>AccessDenied</Code>
	//         <Message>Access Denied</Message>
	//     </Error>
	// </DeleteResult>

	boost::property_tree::ptree document;
	boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
	settings.indent_char = ' ';
	settings.indent_count = 4;
	std::stringstream s;

	// iterate over key_map and write all successes
	bool element_logged = false;
	if (!quiet_flag) {
		for (const auto& [key, value] : key_map) {
			if (value == "Success") {
				element_logged = true;
				boost::property_tree::ptree deleted_element;
				deleted_element.add("Key", key);
				document.add_child("DeleteResult.Deleted", deleted_element);
			}
		}
	}
	// iterate over key_map and write all failures
	for (const auto& [key, value] : key_map) {
		if (value != "Success") {
			element_logged = true;
			boost::property_tree::ptree error_element;
			error_element.add("Key", key);
			error_element.add("Code", value);
			error_element.add("Message", value);
			document.add_child("DeleteResult.Error", error_element);
		}
	}
	if (!element_logged) {
		document.add("DeleteResult", "");
	}

	boost::property_tree::write_xml(s, document, settings);
	response.body() = s.str();
	logging::debug("{}: response\n{}", __func__, s.str());
	response.result(boost::beast::http::status::ok);
	logging::debug("{}: returned [{}]", __func__, response.reason());
	session_ptr->send(std::move(response));
}
