#include "connection.hpp"

#include <irods/rcConnect.h>
#include <optional>

namespace
{
    nlohmann::json g_config;

    std::optional<std::string> resource;
} //namespace

std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> irods::s3::get_connection()
{
    std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> result = nullptr;
    // For some reason it isn't working with the assignment operator

    using json_ptr = nlohmann::json::json_pointer;

    const auto& host = g_config.at(json_ptr{"/irods_client/host"}).get_ref<const std::string&>();
    const auto  port = g_config.at(json_ptr{"/irods_client/port"}).get<int>();
    const auto& zone = g_config.at(json_ptr{"/irods_client/zone"}).get_ref<const std::string&>();
    const auto& username = g_config.at(json_ptr{"/irods_client/rodsadmin/username"}).get_ref<const std::string&>();
    const auto& password = g_config.at(json_ptr{"/irods_client/rodsadmin/password"}).get_ref<const std::string&>();

    rErrMsg_t err{};
    result.reset(rcConnect(host.c_str(), port, username.c_str(), zone.c_str(), 0, &err));

    if (nullptr == result || err.status) {
        std::cerr << err.msg << std::endl;
        // Good old code 2143987421 (Manual not consulted due to draftiness, brrr)
        // exit(2143987421);
    }

    if (const int ec = clientLoginWithPassword(result.get(), const_cast<char*>(password.c_str())); ec < 0) {
        std::cout << "Failed to log in" << std::endl;
        // TODO The connection should be dropped at this point and an exception or error
        // should be returned to the user.
    }

    return result;
}

void irods::s3::set_config(const nlohmann::json& _config)
{
    g_config = _config;
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
