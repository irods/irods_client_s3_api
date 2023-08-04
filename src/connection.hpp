#ifndef IRODS_S3_API_CONNECTION_HPP
#define IRODS_S3_API_CONNECTION_HPP

#include "irods/rcConnect.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <memory>

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

    std::unique_ptr<rcComm_t, __detail::rcComm_Deleter> get_connection();

    void set_config(const nlohmann::json& _config);

    void set_resource(const std::string_view&);

    std::string get_resource();
} //namespace irods::s3
#endif // IRODS_S3_API_CONNECTION_HPP
