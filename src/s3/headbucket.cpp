#include "./s3_api.hpp"
#include "../authentication.hpp"
#include "../bucket.hpp"
#include "../common_routines.hpp"

#include <irods/irods_exception.hpp>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

boost::asio::awaitable<void> irods::s3::actions::handle_headbucket(
    boost::asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    auto conn = irods::s3::get_connection();
    beast::http::response<beast::http::empty_body> response;
    response.result(beast::http::status::forbidden);
    try {
        auto irods_username = irods::s3::authentication::authenticates(*conn, parser, url);

        if (!irods_username) {
            response.result(beast::http::status::forbidden);
        }
        else {
            // Reconnect to the iRODS server as the target user.
            // The rodsadmin account from the config file will act as the proxy for the user.
            conn = irods::s3::get_connection(irods_username);

            fs::path path;
            if (auto bucket = irods::s3::resolve_bucket(*conn, url.segments()); bucket.has_value()) {
                path = irods::s3::finish_path(bucket.value(), url.segments());
            }
            else {
                std::cout << "Failed to resolve bucket" << std::endl;
                response.result(beast::http::status::forbidden);
                beast::http::write(socket, response);
                co_return;
            }
            if (fs::client::exists(*conn, path)) {
                response.result(boost::beast::http::status::ok);
                std::cout << response.result() << std::endl;
            } else {
                // This could be that it doesn't exist or that the user doesn't have permission.
                // Returning forbidden. 
                response.result(boost::beast::http::status::forbidden);
            }
        }
    }
    catch (const std::system_error& e) {
        std::cout << e.what() << std::endl;
        switch (e.code().value()) {
            case USER_ACCESS_DENIED:
            case CAT_NO_ACCESS_PERMISSION:
                response.result(beast::http::status::forbidden);
                break;
            default:
                response.result(beast::http::status::internal_server_error);
                break;
        }
    }

    beast::http::write(socket, response);

    co_return;
}
