#include "irods/private/s3_api/bucket.hpp"

#include "irods/private/s3_api/globals.hpp"
#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"

#include <irods/filesystem.hpp>

#include <algorithm>
#include <string>
#include <utility>

namespace fs = irods::experimental::filesystem;

// Produces the basic irods path of the bucket. This will need concatenation with the remainder of the key.
std::optional<fs::path> irods::s3::resolve_bucket(const boost::urls::segments_view& view)
{
	auto& bucket_mapping = irods::http::globals::bucket_mapping_library();

	using T = decltype(bucket_mapping_collection);
	static auto bm_collection = bucket_mapping.get<T>("bucket_mapping_collection");
	const std::string bucket = *view.begin();
	char* collection{};
	if (bm_collection(bucket.c_str(), &collection) != 0 || !collection) {
		return std::nullopt;
	}

	std::optional<fs::path> opt{std::in_place, collection};
	using U = decltype(bucket_mapping_free);
	static auto bm_free = bucket_mapping.get<U>("bucket_mapping_free");
	bm_free(collection);

	return opt;
} // resolve_bucket

std::optional<std::string> irods::s3::auth_bucket(
	const boost::urls::segments_view& view,
	const nlohmann::json& auth_data)
{
	auto& bucket_mapping = irods::http::globals::bucket_mapping_library();

	using T = decltype(bucket_mapping_map_user);
	static auto bm_auth = bucket_mapping.get<T>("bucket_mapping_map_user");

	const std::string bucket = *view.begin();
	const std::string auth_data_string = auth_data.dump();
	char* user{};

	if (bm_auth(bucket.c_str(), auth_data_string.c_str(), &user) != 0 || !user) {
		return std::nullopt;
	}

	std::optional<std::string> opt{std::in_place, user};
	using U = decltype(bucket_mapping_free);
	static auto bm_free = bucket_mapping.get<U>("bucket_mapping_free");
	bm_free(user);

	return opt;
}

std::pair<std::optional<fs::path>, std::optional<std::string>> irods::s3::resolve_bucket_and_auth(
	const boost::urls::segments_view& view,
	const nlohmann::json& auth_data)
{
	return std::make_pair(resolve_bucket(view), auth_bucket(view, auth_data));
}

fs::path irods::s3::finish_path(const fs::path& base, const boost::urls::segments_view& view)
{
	auto result = base;
	for (auto i = ++view.begin(); i != view.end(); i++) {
		result /= (*i).c_str();
	}
	return result;
} // finish_path
