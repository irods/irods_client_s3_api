#include "connection.hpp"
#include "configuration.hpp"

#include <irods/rcConnect.h>
#include <optional>

std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> irods::s3::get_connection(const std::optional<std::string>& _client_username)
{
    std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> result = nullptr;
    // For some reason it isn't working with the assignment operator

    using json_ptr = nlohmann::json::json_pointer;

    const auto& host = get_config().at(json_ptr{"/irods_client/host"}).get_ref<const std::string&>();
    const auto  port = get_config().at(json_ptr{"/irods_client/port"}).get<int>();
    const auto& zone = get_config().at(json_ptr{"/irods_client/zone"}).get_ref<const std::string&>();
    const auto& username = get_config().at(json_ptr{"/irods_client/proxy_admin_account/username"}).get_ref<const std::string&>();
    const auto& password = get_config().at(json_ptr{"/irods_client/proxy_admin_account/password"}).get_ref<const std::string&>();

    rErrMsg_t err{};

    if (_client_username) {
        result.reset(_rcConnect(host.c_str(), port, username.c_str(), zone.c_str(), _client_username->c_str(), zone.c_str(), &err, 0, 0));
    }
    else {
        result.reset(rcConnect(host.c_str(), port, username.c_str(), zone.c_str(), 0, &err));
    }

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
