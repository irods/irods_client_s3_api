#ifndef IRODS_S3_API_CONFIGURATION_HPP
#define IRODS_S3_API_CONFIGURATION_HPP

#include <nlohmann/json.hpp>

namespace irods::s3
{
    void set_config(const nlohmann::json& _config);
    nlohmann::json& get_config();

    void set_resource(const std::string_view&);
    std::string get_resource();

    uint64_t get_put_object_buffer_size_in_bytes();
    uint64_t get_get_object_buffer_size_in_bytes();

    std::string get_s3_region();

} //namespace irods::s3

#endif //IRODS_S3_API_CONFIGURATION_HPP
