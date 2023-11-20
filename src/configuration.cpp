#include <optional>
#include <nlohmann/json.hpp>

#include "configuration.hpp"

namespace
{
    nlohmann::json g_config;
    std::optional<std::string> resource;
    std::optional<uint64_t> put_object_buffer_size_in_bytes;
    std::optional<uint64_t> put_object_max_buffer_size_in_bytes;
    std::optional<uint64_t> get_object_buffer_size_in_bytes;
    std::optional<std::string> s3_region;
} //namespace

void irods::s3::set_config(const nlohmann::json& _config)
{
    g_config = _config;
}

nlohmann::json& irods::s3::get_config()
{
    return g_config;
}

uint64_t irods::s3::get_put_object_buffer_size_in_bytes()
{
    if (!put_object_buffer_size_in_bytes.has_value()) {
        put_object_buffer_size_in_bytes = g_config.value(
                nlohmann::json::json_pointer{"/s3_server/put_object_buffer_size_in_bytes"}, 8192);
    }
    return put_object_buffer_size_in_bytes.value();
}

uint64_t irods::s3::get_put_object_max_buffer_size_in_bytes()
{
    if (!put_object_max_buffer_size_in_bytes.has_value()) {
        put_object_max_buffer_size_in_bytes = g_config.value(
                nlohmann::json::json_pointer{"/s3_server/put_object_max_buffer_size_in_bytes"}, 65536);
    }
    return put_object_max_buffer_size_in_bytes.value();
}

uint64_t irods::s3::get_get_object_buffer_size_in_bytes()
{
    if (!get_object_buffer_size_in_bytes.has_value()) {
        get_object_buffer_size_in_bytes = g_config.value(
                nlohmann::json::json_pointer{"/s3_server/get_object_buffer_size_in_bytes"}, 8192);
    }
    return get_object_buffer_size_in_bytes.value();
}

std::string irods::s3::get_s3_region()
{
    if (!s3_region.has_value()) {
        s3_region = g_config.value(
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
    if (!resource.has_value()) {
        resource = g_config.value(nlohmann::json::json_pointer{"/s3_server/resource"}, std::string{});
    }
    return resource.value();
}
