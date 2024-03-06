#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/globals.hpp"

#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <string_view>
#include <vector>

#include <boost/url.hpp>
#include <nlohmann/json.hpp>

#include <irods/irods_exception.hpp>
#include <irods/filesystem.hpp>
#include <irods/filesystem/permissions.hpp>
#include <irods/user_administration.hpp>

namespace fs = irods::experimental::filesystem;

std::optional<std::unordered_map<std::string, std::string>> buckets;

std::vector<std::string> list_buckets([[maybe_unused]] rcComm_t* connection, const char* username)
{
	if (!buckets.has_value()) {
		const nlohmann::json& config = irods::http::globals::configuration();
		buckets.emplace();
		for (const auto& [k, v] : config["s3_server"]["plugins"]["static_bucket_resolver"]["mappings"].items()) {
			(*buckets)[k] = v;
		}
	}

	std::vector<std::string> matched;
	auto user = irods::experimental::administration::user(username, connection->clientUser.rodsZone);
	std::unordered_set<std::string> groups;
	{
		auto user_groups = irods::experimental::administration::client::groups(*connection, user);
		std::transform(user_groups.begin(), user_groups.end(), std::inserter(groups, groups.end()), [](const auto& i) {
			return i.name;
		});
	}
	for (const auto& [_key, value] : buckets.value()) {
		//irods::experimental::filesystem::perms perm;

		auto status = irods::experimental::filesystem::client::status(*connection, value);
		for (const auto& p : status.permissions()) {
			if (p.zone != user.zone) {
				continue;
			}
			// This needs to handle groups.
			if (p.name == username && p.prms == irods::experimental::filesystem::perms::own) {
				matched.push_back(_key);
				break;
			}
		}
	}
	return matched;
}

// Produces the basic irods path of the bucket. This will need concatenation with the remainder of the key.
std::optional<fs::path> irods::s3::resolve_bucket(const boost::urls::segments_view& view)
{
	if (!buckets.has_value()) {
		const nlohmann::json& config = irods::http::globals::configuration();
		buckets.emplace();
		for (const auto& [k, v] : config["s3_server"]["plugins"]["static_bucket_resolver"]["mappings"].items()) {
			(*buckets)[k] = v;
		}
	}
	std::string bucket = (*view.begin());
	if (auto i = buckets->find(bucket); i != buckets->end()) {
		fs::path bucket_path(i->second);
		return bucket_path;
	}
	return std::nullopt;
}

fs::path irods::s3::finish_path(const fs::path& base, const boost::urls::segments_view& view)
{
	auto result = base;
	for (auto i = ++view.begin(); i != view.end(); i++) {
		result /= (*i).c_str();
	}
	return result;
}
