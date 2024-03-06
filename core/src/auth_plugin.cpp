#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/globals.hpp"

#include <optional>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <nlohmann/json.hpp>

namespace
{
	struct user
	{
		std::string irods_username;
		std::string secret_key;
	};
	std::optional<std::unordered_map<std::string_view, user>> users;
} //namespace

std::optional<std::string> irods::s3::authentication::get_iRODS_user(const std::string_view access_key)
{
	if (!users.has_value()) {
		const nlohmann::json& config = irods::http::globals::configuration();
		users.emplace();
		for (const auto& [s3_access_key, user_info] :
		     config["s3_server"]["plugins"]["static_authentication_resolver"]["users"].items())
		{
			(*users)[s3_access_key] = user{user_info["username"], user_info["secret_key"]};
		}
	}

	if (users->contains(access_key)) {
		return (*users)[access_key].irods_username;
	}
	return std::nullopt;
}

std::optional<std::string> irods::s3::authentication::get_user_secret_key(const std::string_view access_key)
{
	if (!users.has_value()) {
		const nlohmann::json& config = irods::http::globals::configuration();
		users.emplace();
		for (const auto& [s3_access_key, user_info] :
		     config["s3_server"]["plugins"]["static_authentication_resolver"]["users"].items())
		{
			(*users)[s3_access_key] = user{user_info["username"], user_info["secret_key"]};
		}
	}

	if (users->contains(access_key)) {
		return (*users)[access_key].secret_key;
	}
	return std::nullopt;
}
