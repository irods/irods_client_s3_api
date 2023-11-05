#ifndef IRODS_S3_API_AUTHENTICATION_HPP
#define IRODS_S3_API_AUTHENTICATION_HPP
#include <irods/rcConnect.h>
#include <string>
#include <string_view>
#include <boost/beast.hpp>
#include "types.hpp"
#include <boost/url.hpp>
#include <optional>

namespace irods::s3::authentication
{
    /// Resolves the hashed signature to an iRODS username.
    ///
    /// \param conn The connection to the iRODS server.
    /// \param request The request.
    /// \param url The url
    ///
    /// \returns An iRODS username if the signature is correct, else an empty std::optional.
    std::optional<std::string> authenticates(rcComm_t& conn, const static_buffer_request_parser& request, const boost::urls::url_view& url);

    bool user_exists(rcComm_t& connection, const std::string_view username);
    bool delete_user(rcComm_t& connection, const std::string_view username);
    bool create_user(rcComm_t& connection, const std::string_view username, const std::string_view secret_key);
    bool user_exists(rcComm_t& connection, const std::string_view username);

    std::optional<std::string> get_iRODS_user(rcComm_t* conn, const std::string_view user);
    std::optional<std::string> get_user_secret_key(rcComm_t* conn, const std::string_view user);

} //namespace irods::s3::authentication
#endif
