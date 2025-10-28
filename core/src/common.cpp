#include "irods/private/s3_api/common.hpp"

#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/version.hpp"

#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h> // For addKeyVal().
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h> // For KW_CLOSE_OPEN_REPLICAS.
#include <irods/switch_user.h>

#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
#  include <irods/authenticate.h>
#  include <irods/irods_auth_constants.hpp> // For AUTH_PASSWORD_KEY.
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5

#include <curl/curl.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <type_traits>

template <>
struct fmt::formatter<CURLUcode> : fmt::formatter<std::underlying_type_t<CURLUcode>>
{
	constexpr auto format(const CURLUcode& e, format_context& ctx) const
	{
		return fmt::formatter<std::underlying_type_t<CURLUcode>>::format(
			static_cast<std::underlying_type_t<CURLUcode>>(e), ctx);
	}
};

namespace irods::http
{
	auto fail(response_type& _response, status_type _status, const std::string_view _error_msg) -> response_type
	{
		_response.result(_status);
		_response.set(field_type::server, s3::version::server_name);
		_response.set(field_type::content_type, "application/json");
		_response.body() = _error_msg;
		_response.prepare_payload();
		return _response;
	} // fail

	auto fail(response_type& _response, status_type _status) -> response_type
	{
		return fail(_response, _status, "");
	} // fail

	auto fail(status_type _status, const std::string_view _error_msg) -> response_type
	{
		response_type r{_status, 11};
		return fail(r, _status, _error_msg);
	} // fail

	auto fail(status_type _status) -> response_type
	{
		response_type r{_status, 11};
		return fail(r, _status, "");
	} // fail
} // namespace irods::http

namespace irods
{
	auto get_connection(const std::string& _username) -> irods::http::connection_facade
	{
		using json_pointer = nlohmann::json::json_pointer;

		static const auto& config = irods::http::globals::configuration();
		static const auto& irods_client_config = config.at("irods_client");
		static const auto& zone = irods_client_config.at("zone").get_ref<const std::string&>();

		if (config.at(json_pointer{"/irods_client/enable_4_2_compatibility"}).get<bool>()) {
			static const auto& rodsadmin_username =
				irods_client_config.at(json_pointer{"/proxy_admin_account/username"}).get_ref<const std::string&>();
			static auto rodsadmin_password =
				irods_client_config.at(json_pointer{"/proxy_admin_account/password"}).get_ref<const std::string&>();

			irods::experimental::client_connection conn{
				irods::experimental::defer_authentication,
				irods_client_config.at("host").get_ref<const std::string&>(),
				irods_client_config.at("port").get<int>(),
				{rodsadmin_username, zone},
				{_username, zone}};

			auto* conn_ptr = static_cast<RcComm*>(conn);

#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
			const auto json_input =
				nlohmann::json{{"scheme", "native"}, {irods::AUTH_PASSWORD_KEY, rodsadmin_password}};
			if (const auto ec = rc_authenticate_client(conn_ptr, json_input.dump().c_str()); ec < 0)
#else
			if (const auto ec = clientLoginWithPassword(conn_ptr, rodsadmin_password.data()); ec < 0)
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
			{
				http::logging::error("{}: iRODS authentication error: {}", __func__, ec);
				THROW(SYS_INTERNAL_ERR, "iRODS authentication error.");
			}

			return irods::http::connection_facade{std::move(conn)};
		}

		auto conn = irods::http::globals::connection_pool().get_connection();

		http::logging::trace("{}: Changing identity associated with connection to [{}].", __func__, _username);

		SwitchUserInput input{};

		irods::at_scope_exit clear_options{[&input] { clearKeyVal(&input.options); }};

		irods::strncpy_null_terminated(input.username, _username.c_str());
		irods::strncpy_null_terminated(input.zone, zone.c_str());
		addKeyVal(&input.options, KW_CLOSE_OPEN_REPLICAS, "");

		if (const auto ec = rc_switch_user(static_cast<RcComm*>(conn), &input); ec < 0) {
			http::logging::error("{}: rc_switch_user error: {}", __func__, ec);
			THROW(ec, "rc_switch_user error.");
		}

		http::logging::trace("{}: Successfully changed identity associated with connection to [{}].", __func__, _username);

		return irods::http::connection_facade{std::move(conn)};
	} // get_connection
} // namespace irods
