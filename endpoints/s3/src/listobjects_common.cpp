#include "irods/private/s3_api/listobjects.hpp"

#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/log.hpp"

#include <irods/filesystem.hpp>
#include <irods/irods_query.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/url.hpp>

#include <fmt/format.h>

#include <cstdint>
#include <map>
#include <string>

namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

namespace irods::s3::detail
{
	auto make_ListBucketResult_object(
		const std::string& key,
		const std::string& etag,
		const std::string& owner,
		std::int64_t size,
		const std::string& last_modified,
		bool url_encode_keys) -> boost::property_tree::ptree
	{
		const static std::string_view date_format{"{:%Y-%m-%dT%H:%M:%S.000Z}"};
		boost::property_tree::ptree object;
		object.put("Key", url_encode_keys ? boost::urls::encode(key, boost::urls::unreserved_chars) : key);
		object.put("ETag", etag);
		object.put("Owner", owner);
		object.put("Size", size);
		object.put("StorageClass", "STANDARD");
		try {
			std::time_t modified_epoch_time = boost::lexical_cast<std::time_t>(last_modified);
			std::string modified_time_str =
				irods::s3::api::common_routines::convert_time_t_to_str(modified_epoch_time, date_format);
			object.put("LastModified", modified_time_str);
		}
		catch (const boost::bad_lexical_cast&) {
			// do nothing - don't add LastModified tag
			logging::info(
				"{}: Failed to convert last_modified time [{}]. LastModified tag not added.", __func__, last_modified);
		}
		return object;
	} // make_ListBucketResult_object

	auto make_object_key(const fs::path& irods_path, const fs::path& bucket_base) -> std::string
	{
		const auto path_str = std::string_view{irods_path.c_str()};
		const auto bucket_base_str = std::string_view{bucket_base.c_str()};
		if (path_str.size() <= bucket_base_str.size()) {
			// If the path is not longer than the bucket base, just return an empty string.
			return {};
		}
		auto key = path_str.substr(bucket_base_str.size());
		if (key.starts_with("/")) {
			key = key.substr(1);
		}
		return std::string{key};
	} // make_object_key

	auto get_data_object_info_with_query(RcComm& comm, const std::string& query, data_object_info_map_type& out) -> void
	{
		logging::debug("{}: query=[{}]", __func__, query);

		for (auto&& row : irods::query<RcComm>(&comm, query)) {
			const auto& data_id = row[0];

			const auto p = out.find(data_id);
			if (p == out.end()) {
				// There is no info for this data object in the map. Add it.
				out[data_id] = row;
				continue;
			}

			// If we already have replica info for this object, don't change it unless the replica is good and more
			// recently modified.
			const auto& entry = p->second;
			const auto& this_replica_status = row[6];
			const auto& replica_status_in_map = entry[6];
			if (this_replica_status == replica_status_in_map) {
				// Same status, less recently modified. Do not update it.
				if (std::stoull(row[5]) <= std::stoull(entry[5])) {
					continue;
				}
			}
			else {
				// If the replica in the map has a different status and this replica is not good, that means the replica
				// in the map is good. Do not update it.
				if ("1" != this_replica_status) {
					continue;
				}
			}

			// Add the object info to the map.
			out[data_id] = row;
		}
	} // get_data_object_info_with_query

	auto add_data_object_info_to_ListBucketResult_Contents(
		const data_object_info_map_type& id_to_info,
		const fs::path& bucket_base,
		bool url_encode_keys,
		boost::property_tree::ptree& out) -> void
	{
		for (const auto& id_info_pair : id_to_info) {
			const auto& info = id_info_pair.second;
			const auto path = fs::path{info[1]} / info[2];
			const auto& owner = info[3];
			const auto size = std::stoull(info[4]);
			const auto& mtime = info[5];
			out.add_child(
				"ListBucketResult.Contents",
				make_ListBucketResult_object(
					make_object_key(path, bucket_base), path.c_str(), owner, size, mtime, url_encode_keys));
		}
	} // add_data_object_info_to_ListBucketResult_Contents
} // namespace irods::s3::detail
