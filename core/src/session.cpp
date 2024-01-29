#include "irods/private/s3_api/session.hpp"

#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"

#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/config.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <iterator>
#include <utility>

#ifdef IRODS_WRITE_REQUEST_TO_TEMP_FILE
#  include <fstream>
#endif

namespace irods::http
{
	session::session(
		boost::asio::ip::tcp::socket&& socket,
		const request_handler_map_type& _request_handler_map,
		int _max_body_size,
		int _timeout_in_seconds)
		: stream_(std::move(socket))
		, req_handlers_{&_request_handler_map}
		, max_body_size_{_max_body_size}
		, timeout_in_secs_{_timeout_in_seconds}
	{
	} // session (constructor)

	auto session::ip() const -> std::string
	{
		return stream_.socket().remote_endpoint().address().to_string();
	} // ip

	// Start the asynchronous operation
	auto session::run() -> void
	{
		// We need to be executing within a strand to perform async operations
		// on the I/O objects in this session. Although not strictly necessary
		// for single-threaded contexts, this example code is written to be
		// thread-safe by default.
		boost::asio::dispatch(
			stream_.get_executor(), boost::beast::bind_front_handler(&session::do_read, shared_from_this()));
	} // run

	auto session::do_read() -> void
	{
		// Construct a new parser for each message.
		parser_.emplace();

		// Apply the limit defined in the configuration file.
		parser_->body_limit(max_body_size_);

		// Set the timeout.
		stream_.expires_after(std::chrono::seconds(timeout_in_secs_));

		// Read a request.
		boost::beast::http::async_read(
			stream_, buffer_, *parser_, boost::beast::bind_front_handler(&session::on_read, shared_from_this()));
	} // do_read

	auto session::on_read(boost::beast::error_code ec, std::size_t bytes_transferred) -> void
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == boost::beast::http::error::end_of_stream) {
			return do_close();
		}

		if (ec == boost::beast::http::error::body_limit) {
			logging::error("{}: Request constraint error: {}", __func__, ec.message());
			return;
		}

		if (ec) {
			return irods::fail(ec, "read");
		}

		//
		// Process client request and send a response.
		//

		auto req_ = parser_->release();

		// Print the headers.
		for (auto&& h : req_.base()) {
			logging::debug("{}: Header: ({}, {})", __func__, h.name_string(), h.value());
		}

		// Print the components of the request URL.
		logging::debug("{}: Method: {}", __func__, req_.method_string());
		logging::debug("{}: Version: {}", __func__, req_.version());
		logging::debug("{}: Target: {}", __func__, req_.target());
		logging::debug("{}: Keep Alive: {}", __func__, req_.keep_alive());
		logging::debug("{}: Has Content Length: {}", __func__, req_.has_content_length());
		logging::debug("{}: Chunked: {}", __func__, req_.chunked());
		logging::debug("{}: Needs EOF: {}", __func__, req_.need_eof());

		namespace http = boost::beast::http;

		try {
#ifdef IRODS_WRITE_REQUEST_TO_TEMP_FILE
			std::ofstream{"/tmp/http_request.txt"}.write(req_.body().c_str(), (std::streamsize) req_.body().size());
#endif

			// "host" is a placeholder that's used so that get_url_path() can parse the URL correctly.
			const auto path = irods::http::get_url_path(fmt::format("http://host{}", req_.target()));
			if (!path) {
				send(irods::http::fail(http::status::bad_request));
				return;
			}

			if (const auto iter = req_handlers_->find(*path); iter != std::end(*req_handlers_)) {
				(iter->second)(shared_from_this(), req_);
				return;
			}

			send(irods::http::fail(http::status::not_found));
		}
		catch (const std::exception& e) {
			logging::error("{}: {}", __func__, e.what());
			send(irods::http::fail(http::status::internal_server_error));
		}
	} // on_read

	auto session::on_write(bool close, boost::beast::error_code ec, std::size_t bytes_transferred) -> void
	{
		boost::ignore_unused(bytes_transferred);

		if (ec) {
			return irods::fail(ec, "write");
		}

		if (close) {
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	} // on_write

	auto session::do_close() -> void
	{
		// Send a TCP shutdown.
		boost::beast::error_code ec;
		stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

		// At this point the connection is closed gracefully.
	} // do_close
} // namespace irods::http
