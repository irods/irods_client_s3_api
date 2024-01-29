#ifndef IRODS_S3_API_TRANSPORT_HPP
#define IRODS_S3_API_TRANSPORT_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/url/parse.hpp>

#include <string_view>
#include <memory>

namespace irods::http
{
	class transport
	{
	  public:
		explicit transport(boost::asio::io_context& _ctx);
		virtual ~transport() = default;

		auto connect(std::string_view _host, std::string_view _port) -> void;
		auto is_connected() const noexcept -> bool;
		auto communicate(boost::beast::http::request<boost::beast::http::string_body>& _request)
			-> boost::beast::http::response<boost::beast::http::string_body>;

	  protected:
		virtual auto resolve(std::string_view _host, std::string_view _port)
			-> boost::asio::ip::tcp::resolver::results_type;

	  private:
		virtual auto do_connect(boost::asio::ip::tcp::resolver::results_type& _resolved_host) -> void = 0;
		virtual auto do_write(boost::beast::http::request<boost::beast::http::string_body>& _request) -> void = 0;
		virtual auto do_read() -> boost::beast::http::response<boost::beast::http::string_body> = 0;

		boost::asio::io_context& io_ctx_;
		bool did_connect_;
	}; // class transport

	class tls_transport : public transport
	{
	  public:
		tls_transport(boost::asio::io_context& _ctx, boost::asio::ssl::context& _secure_ctx);
		virtual ~tls_transport();

	  private:
		auto resolve(std::string_view _host, std::string_view _port)
			-> boost::asio::ip::tcp::resolver::results_type override;
		auto do_connect(boost::asio::ip::tcp::resolver::results_type& _resolved_host) -> void override;
		auto do_write(boost::beast::http::request<boost::beast::http::string_body>& _request) -> void override;
		auto do_read() -> boost::beast::http::response<boost::beast::http::string_body> override;
		auto disconnect() -> void;
		auto set_sni_hostname(std::string_view _host) -> void;

		boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
	}; // class tls_transport

	class plain_transport : public transport
	{
	  public:
		explicit plain_transport(boost::asio::io_context& _ctx);
		virtual ~plain_transport();

	  private:
		auto do_connect(boost::asio::ip::tcp::resolver::results_type& _resolved_host) -> void override;
		auto do_write(boost::beast::http::request<boost::beast::http::string_body>& _request) -> void override;
		auto do_read() -> boost::beast::http::response<boost::beast::http::string_body> override;
		auto disconnect() -> void;

		boost::beast::tcp_stream stream_;
	}; // class plain_transport

	auto transport_factory(const boost::urls::scheme& _scheme, boost::asio::io_context& _ctx)
		-> std::unique_ptr<transport>;
} // namespace irods::http

#endif // IRODS_S3_API_TRANSPORT_HPP
