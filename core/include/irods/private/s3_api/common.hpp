#ifndef IRODS_S3_API_ENDPOINT_COMMON_HPP
#define IRODS_S3_API_ENDPOINT_COMMON_HPP

#include <irods/client_connection.hpp>
#include <irods/connection_pool.hpp>
#include <irods/filesystem/object_status.hpp>
#include <irods/filesystem/permissions.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/beast/http/status.hpp>
#include <boost/beast/http/string_body.hpp>

#include <fmt/format.h>

#include <memory>
#include <string>
#include <string_view>
#include <variant>

struct RcComm;

namespace irods::http
{
	class session;

	// clang-format off
	using field_type    = boost::beast::http::field;
	using response_type = boost::beast::http::response<boost::beast::http::string_body>;
	using status_type   = boost::beast::http::status;

	using session_pointer_type = std::shared_ptr<irods::http::session>;
	// clang-format on

	class connection_facade // NOLINT(cppcoreguidelines-special-member-functions)
	{
	  public:
		connection_facade() = default;

		explicit connection_facade(irods::connection_pool::connection_proxy&& _conn)
			: conn_{std::move(_conn)}
		{
		} // constructor

		explicit connection_facade(irods::experimental::client_connection&& _conn)
			: conn_{std::move(_conn)}
		{
		} // constructor

		connection_facade(const connection_facade&) = delete;
		auto operator=(const connection_facade&) -> connection_facade& = delete;

		connection_facade(connection_facade&&) = default;
		auto operator=(connection_facade&&) -> connection_facade& = default;

		explicit operator RcComm*() noexcept
		{
			if (auto* p = std::get_if<irods::connection_pool::connection_proxy>(&conn_); p) {
				return static_cast<RcComm*>(*p);
			}

			return static_cast<RcComm*>(*std::get_if<irods::experimental::client_connection>(&conn_));
		} // operator RcComm*

		operator RcComm&() // NOLINT(google-explicit-constructor)
		{
			if (auto* p = std::get_if<irods::connection_pool::connection_proxy>(&conn_); p) {
				return *p;
			}

			if (auto* p = std::get_if<irods::experimental::client_connection>(&conn_); p) {
				return *p;
			}

			THROW(SYS_INTERNAL_ERR, "Cannot return reference to connection object. connection_facade is empty.");
		} // operator RcComm&

		template <typename T>
		auto get_ref() -> T&
		{
			if (auto* p = std::get_if<T>(&conn_); p) {
				return *p;
			}

			THROW(SYS_INTERNAL_ERR, "Cannot return reference to connection object. connection_facade is empty.");
		} // get_ref

	  private:
		std::variant<std::monostate, irods::experimental::client_connection, irods::connection_pool::connection_proxy>
			conn_;
	}; // class connection_facade

	auto fail(response_type& _response, status_type _status, const std::string_view _error_msg) -> response_type;

	auto fail(response_type& _response, status_type _status) -> response_type;

	auto fail(status_type _status, const std::string_view _error_msg) -> response_type;

	auto fail(status_type _status) -> response_type;
} // namespace irods::http

namespace irods
{
	auto get_connection(const std::string& _username) -> irods::http::connection_facade;

	template <std::size_t N>
	// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
	constexpr auto strncpy_null_terminated(char (&_dst)[N], const char* _src) -> char*
	{
		return std::strncpy(_dst, _src, N - 1);
	} // strncpy_null_terminated
} // namespace irods

#if FMT_VERSION >= 100000 && FMT_VERSION < 110000
template <>
struct fmt::formatter<boost::beast::string_view> : fmt::formatter<std::string_view>
{
	constexpr auto format(const boost::beast::string_view& _str, format_context& ctx) const
	{
		return fmt::formatter<std::string_view>::format(static_cast<std::string_view>(_str), ctx);
	}
};
#endif

#endif // IRODS_S3_API_ENDPOINT_COMMON_HPP
