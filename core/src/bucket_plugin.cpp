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

fs::path irods::s3::finish_path(const fs::path& base, const boost::urls::segments_view& view)
{
	auto result = base;
	for (auto i = ++view.begin(); i != view.end(); i++) {
		result /= (*i).c_str();
	}
	return result;
} // finish_path
