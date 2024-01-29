#ifndef IRODS_S3_API_ENDPOINT_COMMON_HPP
#define IRODS_S3_API_ENDPOINT_COMMON_HPP

#include <irods/client_connection.hpp>
#include <irods/connection_pool.hpp>
#include <irods/filesystem/object_status.hpp>
#include <irods/filesystem/permissions.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/beast/http/status.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/url/parse.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

struct RcComm;

namespace irods::http
{
	class session;

	// clang-format off
	using field_type    = boost::beast::http::field;
	using request_type  = boost::beast::http::request<boost::beast::http::string_body>;
	using response_type = boost::beast::http::response<boost::beast::http::string_body>;
	using status_type   = boost::beast::http::status;
	using verb_type     = boost::beast::http::verb;

	using session_pointer_type = std::shared_ptr<irods::http::session>;
	using request_handler_type = void(*)(session_pointer_type, request_type&);

	using request_handler_map_type = std::unordered_map<std::string_view, request_handler_type>;

	using query_arguments_type = std::unordered_map<std::string, std::string>;

	using handler_type = void (*)(session_pointer_type, request_type&, query_arguments_type&);
	// clang-format on

	enum class authorization_scheme
	{
		basic = 0,
		openid_connect
	}; // enum class authorization_scheme

	struct authenticated_client_info
	{
		authorization_scheme auth_scheme;
		std::string username;
		std::chrono::steady_clock::time_point expires_at; 
		// TODO Store an expiration timestamp here. Post discush: let it expire and send reauth code to client.
		// Perhaps a purge timestamp as well. This is an optimization situation.
	}; // struct authenticated_client_info

	struct url
	{
		std::string path;
		query_arguments_type query;
	}; // struct url

	struct client_identity_resolution_result
	{
		std::optional<response_type> response;
		authenticated_client_info client_info{};
	}; // struct client_identity_resolution_result

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

	auto decode(const std::string_view _v) -> std::string;

	auto encode(std::string_view _to_encode) -> std::string;

	// TODO Create a better name.
	auto to_argument_list(const std::string_view _urlencoded_string) -> std::unordered_map<std::string, std::string>;

	auto get_url_path(const std::string& _url) -> std::optional<std::string>;

	auto parse_url(const std::string& _url) -> url;

	auto parse_url(const request_type& _req) -> url;

	auto resolve_client_identity(const request_type& _req) -> client_identity_resolution_result;

	auto execute_operation(
		session_pointer_type _sess_ptr,
		request_type& _req,
		const std::unordered_map<std::string, handler_type>& _op_table_get,
		const std::unordered_map<std::string, handler_type>& _op_table_post) -> void;

	auto get_port_from_url(boost::urls::url_view _url) -> std::optional<std::string>;
} // namespace irods::http

namespace irods
{
	template <typename Map>
	auto generate_uuid(const Map& _map) -> std::string
	{
		std::string uuid;
		uuid.reserve(36); // NOLINT(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
		uuid = to_string(boost::uuids::random_generator{}());

		while (_map.find(uuid) != std::end(_map)) {
			uuid = to_string(boost::uuids::random_generator{}());
		}

		return uuid;
	} // generate_uuid

	auto to_permission_string(const irods::experimental::filesystem::perms _p) -> const char*;

	auto to_permission_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::perms>;

	auto to_object_type_string(const irods::experimental::filesystem::object_type _t) -> const char*;

	auto to_object_type_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::object_type>;

	auto get_connection(const std::string& _username) -> irods::http::connection_facade;

	auto fail(boost::beast::error_code ec, char const* what) -> void;

	auto enable_ticket(RcComm& _comm, const std::string& _ticket) -> int;

	template <std::size_t N>
	// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
	constexpr auto strncpy_null_terminated(char (&_dst)[N], const char* _src) -> char*
	{
		return std::strncpy(_dst, _src, N - 1);
	} // strncpy_null_terminated
} // namespace irods

#endif // IRODS_S3_API_ENDPOINT_COMMON_HPP
