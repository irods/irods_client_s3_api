#include "irods/private/s3_api/handlers.hpp"

#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/process_stash.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/transport.hpp"
#include "irods/private/s3_api/version.hpp"

#include <irods/base64.hpp>
#include <irods/check_auth_credentials.h>
#include <irods/client_connection.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcConnect.h>
#include <irods/user_administration.hpp>

#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
#  include <irods/authenticate.h>
#  include <irods/irods_auth_constants.hpp> // For AUTH_PASSWORD_KEY.
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/url/parse.hpp>

#include <nlohmann/json.hpp>
#include <fmt/core.h>

#include <curl/curl.h>
#include <curl/urlapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <iterator>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
// clang-format on

namespace irods::http::handler
{
	auto decode_username_and_password(std::string_view _encoded_data) -> std::pair<std::string, std::string>
	{
		std::string authorization{_encoded_data};
		boost::trim(authorization);
		logging::debug("{}: Authorization value (trimmed): [{}]", __func__, authorization);

		constexpr auto max_creds_size = 128;
		std::uint64_t size{max_creds_size};
		std::array<std::uint8_t, max_creds_size> creds{};
		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
		const auto ec = irods::base64_decode(
			reinterpret_cast<unsigned char*>(authorization.data()), authorization.size(), creds.data(), &size);
		logging::debug("{}: base64 - error code=[{}], decoded size=[{}]", __func__, ec, size);

		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
		std::string_view sv{reinterpret_cast<char*>(creds.data()), size};

		const auto colon = sv.find(':');
		if (colon == std::string_view::npos) {
			return {"", ""};
		}

		std::string username{sv.substr(0, colon)};
		std::string password{sv.substr(colon + 1)};

		return {std::move(username), std::move(password)};
	}

	IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(authentication)
	{
		if (_req.method() != boost::beast::http::verb::post) {
			logging::error("{}: HTTP method not supported.", __func__);
			return _sess_ptr->send(fail(status_type::method_not_allowed));
		}

		irods::http::globals::background_task([fn = __func__, _sess_ptr, _req = std::move(_req)] {
			const auto& hdrs{_req.base()};
			const auto iter{hdrs.find("authorization")};

			if (iter == std::end(hdrs)) {
				return _sess_ptr->send(fail(status_type::bad_request));
			}

			logging::debug("{}: Authorization value: [{}]", fn, iter->value());

			const auto pos = iter->value().find("Basic ");
			if (pos == std::string_view::npos) {
				return _sess_ptr->send(fail(status_type::bad_request));
			}

			constexpr auto basic_auth_scheme_prefix_size = 6;
			auto [username, password]{
				decode_username_and_password(iter->value().substr(pos + basic_auth_scheme_prefix_size))};

			static const auto seconds =
				irods::http::globals::configuration()
					.at(nlohmann::json::json_pointer{"/s3_server/authentication/basic/timeout_in_seconds"})
					.get<int>();

			// The anonymous user account must be handled in a special way because rc_check_auth_credentials
			// doesn't support it. To get around that, the S3 API will return a bearer token whenever the
			// anonymous user is seen. If the iRODS zone doesn't contain an anonymous user, any request sent
			// by the client will result in an error.
			//
			// The error will occur when rc_switch_user is invoked on the non-existent user.
			if ("anonymous" == username && password.empty()) {
				logging::trace("{}: Detected the anonymous user account. Skipping auth check and returning token.", fn);

				auto bearer_token = irods::http::process_stash::insert(authenticated_client_info{
					.auth_scheme = authorization_scheme::basic,
					.username = std::move(username),
					.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

				response_type res{status_type::ok, _req.version()};
				res.set(field_type::server, irods::s3::version::server_name);
				res.set(field_type::content_type, "text/plain");
				res.keep_alive(_req.keep_alive());
				res.body() = std::move(bearer_token);
				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			}

			if (username.empty() || password.empty()) {
				return _sess_ptr->send(fail(status_type::unauthorized));
			}

			bool login_successful = false;

			try {
				using json_pointer = nlohmann::json::json_pointer;

				static const auto& config = irods::http::globals::configuration();
				static const auto& rodsadmin_username =
					config.at(json_pointer{"/irods_client/proxy_admin_account/username"}).get_ref<const std::string&>();
				static const auto& rodsadmin_password =
					config.at(json_pointer{"/irods_client/proxy_admin_account/password"}).get_ref<const std::string&>();
				static const auto& zone = config.at(json_pointer{"/irods_client/zone"}).get_ref<const std::string&>();

				if (config.at(json_pointer{"/irods_client/enable_4_2_compatibility"}).get<bool>()) {
					// When operating in 4.2 compatibility mode, all we can do is create a new iRODS connection
					// and authenticate using the client's username and password. iRODS 4.2 does not provide an
					// API for checking native authentication credentials.

					const auto& host = config.at(json_pointer{"/irods_client/host"}).get_ref<const std::string&>();
					const auto port = config.at(json_pointer{"/irods_client/port"}).get<int>();

					irods::experimental::client_connection conn{
						irods::experimental::defer_authentication, host, port, {username, zone}};

#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
					// clang-format off
					login_successful =
						(rc_authenticate_client(
							 static_cast<RcComm*>(conn),
							 nlohmann::json{
								 {"scheme", "native"},
								 {irods::AUTH_PASSWORD_KEY, password}
							 }.dump().c_str()) == 0);
					// clang-format on
#else
					login_successful = (clientLoginWithPassword(static_cast<RcComm*>(conn), password.data()) == 0);
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
				}
				else {
					// If we're in this branch, assume we're talking to an iRODS 4.3.1+ server. Therefore, we
					// can use existing iRODS connections to verify the correctness of client provided
					// credentials for native authentication.

					CheckAuthCredentialsInput input{};
					username.copy(input.username, sizeof(CheckAuthCredentialsInput::username));
					zone.copy(input.zone, sizeof(CheckAuthCredentialsInput::zone));

					namespace adm = irods::experimental::administration;
					const adm::user_password_property prop{password, rodsadmin_password};
					const auto obfuscated_password = irods::experimental::administration::obfuscate_password(prop);
					obfuscated_password.copy(input.password, sizeof(CheckAuthCredentialsInput::password));

					int* correct{};

					// NOLINTNEXTLINE(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
					irods::at_scope_exit free_memory{[&correct] { std::free(correct); }};

					auto conn = irods::get_connection(rodsadmin_username);

					if (const auto ec = rc_check_auth_credentials(static_cast<RcComm*>(conn), &input, &correct); ec < 0)
					{
						logging::error(
							"{}: Error verifying native authentication credentials for user [{}]: error code "
							"[{}].",
							fn,
							username,
							ec);
					}
					else {
						logging::debug("{}: correct = [{}]", fn, fmt::ptr(correct));
						logging::debug("{}: *correct = [{}]", fn, (correct ? *correct : -1));
						login_successful = (correct && 1 == *correct);
					}
				}
			}
			catch (const irods::exception& e) {
				logging::error(
					"{}: Error verifying native authentication credentials for user [{}]: {}",
					fn,
					username,
					e.client_display_what());
			}
			catch (const std::exception& e) {
				logging::error(
					"{}: Error verifying native authentication credentials for user [{}]: {}", fn, username, e.what());
			}

			if (!login_successful) {
				return _sess_ptr->send(fail(status_type::unauthorized));
			}

			auto bearer_token = irods::http::process_stash::insert(authenticated_client_info{
				.auth_scheme = authorization_scheme::basic,
				.username = std::move(username),
				.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

			response_type res{status_type::ok, _req.version()};
			res.set(field_type::server, irods::s3::version::server_name);
			res.set(field_type::content_type, "text/plain");
			res.keep_alive(_req.keep_alive());
			res.body() = std::move(bearer_token);
			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // authentication
} //namespace irods::http::handler
