#ifndef IRODS_S3_API_LISTOBJECTS_DETAIL_HPP
#define IRODS_S3_API_LISTOBJECTS_DETAIL_HPP

#include <irods/filesystem.hpp>
#include <irods/irods_query.hpp>

#include <boost/property_tree/ptree.hpp>

#include <cstdint>
#include <map>
#include <string>

struct RcComm;

namespace irods::s3::detail
{
	using data_object_info_map_type = std::map<std::string, irods::query<RcComm>::value_type>;

	auto make_ListBucketResult_object(
		const std::string& key,
		const std::string& etag,
		const std::string& owner,
		std::int64_t size,
		const std::string& last_modified,
		bool url_encode_keys) -> boost::property_tree::ptree;

	// Makes an S3 object key out of an iRODS logical path by stripping the iRODS collection for the base bucket.
	auto make_object_key(
		const irods::experimental::filesystem::path& irods_path,
		const irods::experimental::filesystem::path& bucket_base) -> std::string;

	// Helper function which takes a query for data object information and updates the passed in map with information
	// using the latest, marked-good replica. If there are no good replicas, the replica with the latest modify time
	// is used. The query must select the following, in order:
	// DATA_ID, COLL_NAME, DATA_NAME, DATA_OWNER_NAME, DATA_SIZE, DATA_MODIFY_TIME, DATA_REPL_STATUS
	auto get_data_object_info_with_query(RcComm& comm, const std::string& query, data_object_info_map_type& out)
		-> void;

	// Helper function which takes data object query results and adds them to the ListBucketResult "Contents" key.
	auto add_data_object_info_to_ListBucketResult_Contents(
		const data_object_info_map_type& id_to_info,
		const irods::experimental::filesystem::path& bucket_base,
		bool url_encode_keys,
		boost::property_tree::ptree& out) -> void;
} // namespace irods::s3::detail

#endif // IRODS_S3_API_LISTOBJECTS_DETAIL_HPP
