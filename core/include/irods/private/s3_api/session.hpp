#ifndef IRODS_S3_API_SESSION_HPP
#define IRODS_S3_API_SESSION_HPP

#include "irods/private/s3_api/common.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <memory>
#include <optional>

namespace irods::http
{
	class session : public std::enable_shared_from_this<session>
	{
	  public:
		session(
			boost::asio::ip::tcp::socket&& socket,
			const request_handler_map_type& _request_handler_map,
			int _max_body_size,
			int _timeout_in_seconds);

		auto ip() const -> std::string;

		auto run() -> void;

		auto do_read() -> void;

		auto on_read(boost::beast::error_code ec, std::size_t bytes_transferred) -> void;

		auto on_write(bool close, boost::beast::error_code ec, std::size_t bytes_transferred) -> void;

		auto do_close() -> void;

		auto stream() -> boost::beast::tcp_stream&
		{
			return stream_;
		} // stream

		template <bool isRequest, class Body, class Fields>
		auto send(boost::beast::http::message<isRequest, Body, Fields>&& msg) -> void
		{
			namespace http = boost::beast::http;

			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			res_ = sp;

			// Write the response.
			http::async_write(
				stream_, *sp, boost::beast::bind_front_handler(&session::on_write, shared_from_this(), sp->need_eof()));
		} // send

	  private:
		boost::beast::tcp_stream stream_;
		boost::beast::flat_buffer buffer_;
		std::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser_;
		std::shared_ptr<void> res_; // TODO Probably doesn't need to be a shared_ptr anymore. The session owns it and is
		                            // available for the lifetime of the request.
		const request_handler_map_type* req_handlers_;
		const int max_body_size_;
		const int timeout_in_secs_;
	}; // class session
} // namespace irods::http

#endif // IRODS_S3_API_SESSION_HPP
