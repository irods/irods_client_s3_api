#include <optional>
#include <nlohmann/json.hpp>

#include "configuration.hpp"

namespace
{
    nlohmann::json g_config;
    std::optional<std::string> resource;
    std::optional<uint64_t> read_buffer_size_in_bytes;
    std::optional<uint64_t> write_buffer_size_in_bytes;
} //namespace

void irods::s3::set_config(const nlohmann::json& _config)
{
    g_config = _config;
}

nlohmann::json& irods::s3::get_config()
{
    return g_config;
}

uint64_t irods::s3::get_read_buffer_size_in_bytes()
{
    if (!read_buffer_size_in_bytes.has_value()) {
        read_buffer_size_in_bytes = g_config.value(
                nlohmann::json::json_pointer{"/s3_server/read_buffer_size_in_bytes"}, 8192);
    }
    return read_buffer_size_in_bytes.value();
}

uint64_t irods::s3::get_write_buffer_size_in_bytes()
{
    if (!write_buffer_size_in_bytes.has_value()) {
        write_buffer_size_in_bytes = g_config.value(
                nlohmann::json::json_pointer{"/s3_server/write_buffer_size_in_bytes"}, 8192);
    }
    return write_buffer_size_in_bytes.value();
}

void irods::s3::set_resource(const std::string_view& resc)
{
    resource = resc;
}

std::string irods::s3::get_resource()
{
    if (!resource.has_value()) {
        resource = g_config.value(nlohmann::json::json_pointer{"/resource"}, std::string{});
    }
    return resource.value();
}
