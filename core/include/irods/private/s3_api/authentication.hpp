#ifndef IRODS_S3_API_AUTHENTICATION_HPP
#define IRODS_S3_API_AUTHENTICATION_HPP

#include <irods/rcConnect.h>
#include <string>
#include <string_view>
#include <boost/beast.hpp>
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
    std::optional<std::string> authenticates(
            const boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
            const boost::urls::url_view& url);

    std::optional<std::string> get_iRODS_user(const std::string_view access_key);
    std::optional<std::string> get_user_secret_key(const std::string_view access_key);

} //namespace irods::s3::authentication
#endif
