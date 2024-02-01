#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/configuration.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"

#include <irods/rcConnect.h>
#include <optional>

std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> irods::s3::get_connection(const std::optional<std::string>& _client_username)
{
    namespace log = irods::http::log;
    std::unique_ptr<rcComm_t, irods::s3::__detail::rcComm_Deleter> result = nullptr;
    // For some reason it isn't working with the assignment operator

    using json_ptr = nlohmann::json::json_pointer;

    const auto& host = irods::http::globals::configuration().at(json_ptr{"/irods_client/host"}).get_ref<const std::string&>();
    const auto  port = irods::http::globals::configuration().at(json_ptr{"/irods_client/port"}).get<int>();
    const auto& zone = irods::http::globals::configuration().at(json_ptr{"/irods_client/zone"}).get_ref<const std::string&>();
    const auto& username = irods::http::globals::configuration().at(json_ptr{"/irods_client/proxy_admin_account/username"}).get_ref<const std::string&>();
    const auto& password = irods::http::globals::configuration().at(json_ptr{"/irods_client/proxy_admin_account/password"}).get_ref<const std::string&>();

    rErrMsg_t err{};

    if (_client_username) {
        result.reset(_rcConnect(host.c_str(), port, username.c_str(), zone.c_str(), _client_username->c_str(), zone.c_str(), &err, 0, 0));
    }
    else {
        result.reset(rcConnect(host.c_str(), port, username.c_str(), zone.c_str(), 0, &err));
    }

    if (nullptr == result || err.status) {
        log::error(err.msg);
    }

    if (const int ec = clientLoginWithPassword(result.get(), const_cast<char*>(password.c_str())); ec < 0) {
        log::error("Failed to log in");
        // TODO The connection should be dropped at this point and an exception or error
        // should be returned to the user.
    }

    return result;
}
