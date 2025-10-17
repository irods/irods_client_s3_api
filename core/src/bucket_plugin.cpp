#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"

#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/user_administration.hpp>

#include <boost/url.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = irods::experimental::filesystem;

std::vector<std::string> list_buckets(rcComm_t* connection, const char* username)
{
	auto& bucket_mapping = irods::http::globals::bucket_mapping_library();

	using T = decltype(bucket_mapping_list);
	static auto bm_list = bucket_mapping.get<T>("bucket_mapping_list");
	bucket_mapping_entry_t* entries{};
	size_t count{};
	if (bm_list(&entries, &count) != 0 || !entries || 0 == count) {
		return {};
	}

	irods::at_scope_exit free_memory{[&entries, count, &bucket_mapping] {
		if (!entries) {
			return;
		}

		using T = decltype(bucket_mapping_free);
		auto bm_free = bucket_mapping.get<T>("bucket_mapping_free");
		std::for_each(entries, entries + count, [&bm_free](bucket_mapping_entry& e) {
			bm_free(e.bucket);
			bm_free(e.collection);
		});
		bm_free(entries);
	}};

	auto user = irods::experimental::administration::user(username, connection->clientUser.rodsZone);
	std::unordered_set<std::string> groups;
	{
		auto user_groups = irods::experimental::administration::client::groups(*connection, user);
		std::transform(user_groups.begin(), user_groups.end(), std::inserter(groups, groups.end()), [](const auto& i) {
			return i.name;
		});
	}

	std::vector<std::string> matched;

	// TODO(#178): Using GenQuery2 directly is likely faster since it can filter out unnecessary entries.
	const auto is_owner = [&user](const auto& _p) {
		return _p.prms == irods::experimental::filesystem::perms::own && _p.zone == user.zone && _p.name == user.name;
	};

	for (size_t i = 0; i < count; ++i) {
		const auto status = irods::experimental::filesystem::client::status(*connection, entries[i].collection);

		// TODO(#178): This needs to handle groups.
		if (std::any_of(std::begin(status.permissions()), std::end(status.permissions()), is_owner)) {
			matched.emplace_back(entries[i].bucket);
		}
	}

	return matched;
} // list_buckets

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

fs::path irods::s3::finish_path(const fs::path& base, const boost::urls::segments_view& view)
{
	auto result = base;
	for (auto i = ++view.begin(); i != view.end(); i++) {
		result /= (*i).c_str();
	}
	return result;
} // finish_path
