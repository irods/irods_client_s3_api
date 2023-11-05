#ifndef IRODS_S3_API_CONNECTION_HPP
#define IRODS_S3_API_CONNECTION_HPP

#include "irods/rcConnect.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace irods::s3
{
    namespace __detail
    {
        struct rcComm_Deleter
        {
            rcComm_Deleter() = default;
            constexpr void operator()(rcComm_t* conn) const noexcept
            {
                if (conn == nullptr) {
                    return;
                }
                rcDisconnect(conn);
            }
        };
    } //namespace __detail

    using connection_handle = std::unique_ptr<rcComm_t, __detail::rcComm_Deleter>;

    std::unique_ptr<rcComm_t, __detail::rcComm_Deleter> get_connection(const std::optional<std::string>& _client_username = std::nullopt);
} //namespace irods::s3
#endif // IRODS_S3_API_CONNECTION_HPP
