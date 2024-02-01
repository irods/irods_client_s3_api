#include <optional>
#include <nlohmann/json.hpp>

#include "irods/private/s3_api/configuration.hpp"
#include "irods/private/s3_api/globals.hpp"

namespace
{
    std::optional<std::string> resource;
    std::optional<uint64_t> put_object_buffer_size_in_bytes;
    std::optional<uint64_t> get_object_buffer_size_in_bytes;
    std::optional<std::string> s3_region;
} //namespace

uint64_t irods::s3::get_put_object_buffer_size_in_bytes()
{
    const nlohmann::json& config = irods::http::globals::configuration();
    if (!put_object_buffer_size_in_bytes.has_value()) {
        put_object_buffer_size_in_bytes = config.value(
                nlohmann::json::json_pointer{"/irods_client/put_object_buffer_size_in_bytes"}, 8192);
    }
    return put_object_buffer_size_in_bytes.value();
}

uint64_t irods::s3::get_get_object_buffer_size_in_bytes()
{
    const nlohmann::json& config = irods::http::globals::configuration();
    if (!get_object_buffer_size_in_bytes.has_value()) {
        get_object_buffer_size_in_bytes = config.value(
                nlohmann::json::json_pointer{"/irods_client/get_object_buffer_size_in_bytes"}, 8192);
    }
    return get_object_buffer_size_in_bytes.value();
}

std::string irods::s3::get_s3_region()
{
    const nlohmann::json& config = irods::http::globals::configuration();
    if (!s3_region.has_value()) {
        s3_region = config.value(
                nlohmann::json::json_pointer{"/s3_server/region"}, "us-east-1");
    }
    return s3_region.value();
}

void irods::s3::set_resource(const std::string_view& resc)
{
    resource = resc;
}

std::string irods::s3::get_resource()
{
    const nlohmann::json& config = irods::http::globals::configuration();
    if (!resource.has_value()) {
        resource = config.value(nlohmann::json::json_pointer{"/irods_client/resource"}, std::string{});
    }
    return resource.value();
}
