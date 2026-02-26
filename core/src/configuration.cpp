#include "irods/private/s3_api/configuration.hpp"

#include "irods/private/s3_api/globals.hpp"

#include <nlohmann/json.hpp>

#include <optional>

uint64_t irods::s3::get_put_object_buffer_size_in_bytes()
{
	const nlohmann::json& config = irods::http::globals::configuration();
	return config.value(nlohmann::json::json_pointer{"/irods_client/put_object_buffer_size_in_bytes"}, 8192);
}

uint64_t irods::s3::get_get_object_buffer_size_in_bytes()
{
	const nlohmann::json& config = irods::http::globals::configuration();
	return config.value(nlohmann::json::json_pointer{"/irods_client/get_object_buffer_size_in_bytes"}, 8192);
}

std::string irods::s3::get_s3_region()
{
	const nlohmann::json& config = irods::http::globals::configuration();
	return config.value(nlohmann::json::json_pointer{"/s3_server/region"}, "us-east-1");
}

std::string irods::s3::get_resource()
{
	const nlohmann::json& config = irods::http::globals::configuration();
	return config.value(nlohmann::json::json_pointer{"/irods_client/resource"}, std::string{});
}
