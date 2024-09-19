#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/configuration.hpp"
#include "irods/private/s3_api/globals.hpp"

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
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

using irods_connection = irods::http::connection_facade;
using irods_default_transport = irods::experimental::io::client::default_transport;
using buffer_body_serializer = beast::http::response_serializer<beast::http::buffer_body>;
using buffer_body_response = beast::http::response<beast::http::buffer_body>;

// These are things that need to persist and will be wrapped in std::shared_ptr
namespace
{
	struct persistent_data
	{
		persistent_data(std::shared_ptr<irods::experimental::client_connection> conn, fs::path path)
			: conn_ptr{conn}
			, serializer{response}
			, xtrans{*conn}
			, d{xtrans, path, irods::experimental::io::root_resource_name{irods::s3::get_resource()}, std::ios_base::in}
		{
		}

		std::shared_ptr<irods::experimental::client_connection> conn_ptr;
		buffer_body_response response;
		buffer_body_serializer serializer;
		irods_default_transport xtrans;
		irods::experimental::io::idstream d;
	};
} //namespace

void read_from_irods_send_to_client(
	irods::http::session_pointer_type session_ptr,
	std::shared_ptr<persistent_data> vars,
	std::size_t range_start,
	std::size_t range_end,
	std::size_t offset,
	uint64_t write_buffer_size,
	const std::string func);

const static std::string_view date_format{"{:%a, %d %b %Y %H:%M:%S GMT}"};

void irods::s3::actions::handle_getobject(
	irods::http::session_pointer_type session_ptr,
	beast::http::request_parser<boost::beast::http::empty_body>& parser,
	const boost::urls::url_view& url)
{
	using json_pointer = nlohmann::json::json_pointer;

	beast::http::response<beast::http::empty_body> response;

	auto irods_username = irods::s3::authentication::authenticates(parser, url);
	if (!irods_username) {
		logging::error("{}: Failed to authenticate.", __FUNCTION__);
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	fs::path path;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		path = bucket.value();
		path = irods::s3::finish_path(path, url.segments());
	}
	else {
		logging::error("{}: Failed to resolve bucket", __FUNCTION__);
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	const auto& config = irods::http::globals::configuration();
	const auto& irods_client_config = config.at("irods_client");
	const auto& zone = irods_client_config.at("zone").get_ref<const std::string&>();

	const auto& rodsadmin_username =
		irods_client_config.at(json_pointer{"/proxy_admin_account/username"}).get_ref<const std::string&>();
	auto rodsadmin_password =
		irods_client_config.at(json_pointer{"/proxy_admin_account/password"}).get_ref<const std::string&>();

	auto conn = std::make_shared<irods::experimental::client_connection>(
		irods::experimental::defer_authentication,
		irods_client_config.at("host").get_ref<const std::string&>(),
		irods_client_config.at("port").get<int>(),
		irods::experimental::fully_qualified_username{rodsadmin_username, zone},
		irods::experimental::fully_qualified_username{*irods_username, zone});

	auto* conn_ptr = static_cast<RcComm*>(*conn);

	if (const auto ec = clientLoginWithPassword(conn_ptr, rodsadmin_password.data()); ec < 0) {
		logging::error("{}: clientLoginWithPassword error: {}", __func__, ec);
		response.result(beast::http::status::internal_server_error);
		session_ptr->send(std::move(response));
		return;
	}

	std::shared_ptr<persistent_data> persistent_data_ptr = std::make_shared<persistent_data>(conn, path);

	// read the range header if it exists
	// Note:  We are only implementing range headers in the format range: bytes=<start>-[end]
	std::size_t range_start = 0;
	std::size_t range_end = 0;
	auto range_header = parser.get().find("range");
	if (range_header != parser.get().end()) {
		if (range_header->value().starts_with("bytes=")) {
			std::string range = range_header->value().substr(6);

			std::vector<std::string> range_parts;
			boost::split(range_parts, range, boost::is_any_of("-"));

			if (range_parts.size() != 2) {
				logging::error("{}: The provided range format has not been implemented.", __FUNCTION__);
				response.result(beast::http::status::not_implemented);
				logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
				session_ptr->send(std::move(response));
				return;
			}

			try {
				range_start = boost::lexical_cast<std::size_t>(range_parts[0]);
				if (!range_parts[1].empty()) {
					range_end = boost::lexical_cast<std::size_t>(range_parts[1]);
				}
			}
			catch (const boost::bad_lexical_cast&) {
				logging::error("{}: Could not cast the start or end range to a size_t.", __FUNCTION__);
				response.result(beast::http::status::not_implemented);
				logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
				session_ptr->send(std::move(response));
				return;
			}
		}
		else {
			logging::error(
				"{}: The provided range format has not been implemented - does not begin with \"bytes=\".",
				__FUNCTION__);
			response.result(beast::http::status::not_implemented);
			logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
			session_ptr->send(std::move(response));
			return;
		}
	}

	try {
		if (fs::client::exists(*(persistent_data_ptr->conn_ptr), path)) {
			uint64_t write_buffer_size = irods::s3::get_get_object_buffer_size_in_bytes();

			auto file_size =
				irods::experimental::filesystem::client::data_object_size(*(persistent_data_ptr->conn_ptr), path);
			if (range_end == 0 || range_end > file_size - 1) {
				range_end = file_size - 1;
			}
			auto content_length = range_end - range_start + 1; // ranges are inclusive

			// Set the Content-Length header
			std::string length_field = std::to_string(content_length);
			persistent_data_ptr->response.insert(beast::http::field::content_length, length_field);

			// Get the file MD5 and set the Content-MD5 header
			auto md5 =
				irods::experimental::filesystem::client::data_object_checksum(*(persistent_data_ptr->conn_ptr), path);
			persistent_data_ptr->response.insert("Content-MD5", md5);

			// Get the last write time and set the Last-Mofified header
			auto last_write_time__time_point =
				irods::experimental::filesystem::client::last_write_time(*(persistent_data_ptr->conn_ptr), path);
			std::time_t last_write_time__time_t = std::chrono::system_clock::to_time_t(last_write_time__time_point);
			std::string last_write_time__str =
				irods::s3::api::common_routines::convert_time_t_to_str(last_write_time__time_t, date_format);
			persistent_data_ptr->response.insert(beast::http::field::last_modified, last_write_time__str);

			// seek to the start range
			persistent_data_ptr->d.seekg(range_start);
			size_t offset = range_start;

			if (persistent_data_ptr->d.fail() || persistent_data_ptr->d.bad()) {
				logging::error("{}: Fail/badbit set", __FUNCTION__);
				persistent_data_ptr->response.result(beast::http::status::forbidden);
				persistent_data_ptr->response.body().more = false;
				logging::debug("{}: returned [{}]", __FUNCTION__, persistent_data_ptr->response.reason());
				session_ptr->send(std::move(persistent_data_ptr->response));
				return;
			}
			beast::error_code ec;
			beast::http::write_header(session_ptr->stream().socket(), persistent_data_ptr->serializer, ec);
			if (ec) {
				persistent_data_ptr->response.result(beast::http::status::internal_server_error);
				logging::debug("{}: returned [{}]", __FUNCTION__, persistent_data_ptr->response.reason());
				session_ptr->send(std::move(persistent_data_ptr->response));
				return;
			}

			// set the response to ok
			persistent_data_ptr->response.result(beast::http::status::ok);

			read_from_irods_send_to_client(
				session_ptr, persistent_data_ptr, range_start, range_end, offset, write_buffer_size, __FUNCTION__);
		}
		else {
			return irods::s3::api::common_routines::send_error_response(
				session_ptr,
				boost::beast::http::status::not_found,
				"NoSuchKey",
				"Object does not exist",
				url.path(),
				__FUNCTION__);
		}
	}
	catch (irods::exception& e) {
		logging::error("{}: Exception {}", __FUNCTION__, e.what());

		switch (e.code()) {
			case USER_ACCESS_DENIED:
			case CAT_NO_ACCESS_PERMISSION:
				response.result(beast::http::status::forbidden);
				break;
			default:
				response.result(beast::http::status::internal_server_error);
				break;
		}

		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
	}
	catch (std::exception& e) {
		logging::error("{}: Exception {}", __FUNCTION__, e.what());
		response.result(beast::http::status::internal_server_error);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
	}
	catch (...) {
		logging::error("{}: Unknown exception encountered", __FUNCTION__);
		response.result(beast::http::status::internal_server_error);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
	}

	// all paths should have a return here
}

void read_from_irods_send_to_client(
	irods::http::session_pointer_type session_ptr,
	std::shared_ptr<persistent_data> persistent_data_ptr,
	std::size_t range_start,
	std::size_t range_end,
	std::size_t offset,
	uint64_t write_buffer_size,
	const std::string func)
{
	irods::http::globals::background_task(
		[session_ptr, persistent_data_ptr, range_start, range_end, offset, write_buffer_size, func]() mutable {
			std::vector<char> buf_vector(write_buffer_size);

			std::streampos current, size;

			// Determine the length we need to read which is the smaller
		    // of the write_buffer_size or the bytes to the end of the range.
		    // Note that ranges are inclusive which is why the +1's exist.
			std::size_t read_length =
				write_buffer_size < range_end + 1 - offset ? write_buffer_size : range_end + 1 - offset;

			// read from iRODS
			persistent_data_ptr->d.read(buf_vector.data(), read_length);
			current = persistent_data_ptr->d.gcount();
			offset += current;
			size += current;
			persistent_data_ptr->response.body().data = buf_vector.data();
			persistent_data_ptr->response.body().size = current;
			if (persistent_data_ptr->d.bad()) {
				// An error occurred on reading from iRODS. We have already sent
			    // the response in the header. All we can do is bail.
				logging::error("{}: Badbit set on read from iRODS. Bailing...", func);
				return;
			}

			// write to socket
			boost::beast::error_code ec;
			beast::http::write(session_ptr->stream().socket(), persistent_data_ptr->serializer, ec);
			if (ec == beast::http::error::need_buffer) {
				ec = {};
			}
			else if (ec) {
				// An error occurred writing the body data. We have already sent
			    // the response in the header. All we can do is bail.
				logging::error("{}: Error {} occurred while sending socket data. Bailing...", func, ec.message());
				return;
			}

			logging::trace("{}: Wrote {} bytes total.  offset={}", func, size, offset);

			// If we have now read beyond the range_end then we are done. Return.
			if (offset > range_end) {
				persistent_data_ptr->response.body().more = false;
				logging::debug(
					"{} returned [{}] error={}", __FUNCTION__, persistent_data_ptr->response.reason(), ec.message());
				return;
			}

			read_from_irods_send_to_client(
				session_ptr, persistent_data_ptr, range_start, range_end, offset, write_buffer_size, func);
		});
}
