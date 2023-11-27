#include "s3_api.hpp"

#include "../connection.hpp"
#include "../bucket.hpp"
#include "../authentication.hpp"

#include <irods/filesystem.hpp>

#include <irods/filesystem/collection_entry.hpp>
#include <irods/filesystem/collection_iterator.hpp>
#include <irods/filesystem/filesystem.hpp>
#include <irods/filesystem/filesystem_error.hpp>
#include <irods/filesystem/path.hpp>
#include <irods/genQuery.h>
#include <irods/irods_exception.hpp>
#include <irods/msParam.h>
#include <irods/rcConnect.h>
#include <irods/rodsClient.h>
#include <irods/irods_client_api_table.hpp>
#include <irods/irods_pack_table.hpp>
#include <irods/irods_parse_command_line_options.hpp>
#include <irods/filesystem.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsGenQuery.h>
#include <irods/rodsPath.h>
#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>
#include <irods/irods_query.hpp>
#include <irods/query_builder.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/stacktrace.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

asio::awaitable<void> irods::s3::actions::handle_deleteobject(
    asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    auto conn = irods::s3::get_connection();
    auto url_and_stuff = boost::urls::url_view(parser.get().base().target());

    // Permission verification stuff should go roughly here.

    auto irods_username = irods::s3::authentication::authenticates(*conn, parser, url);
    if (!irods_username) {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::forbidden);
        beast::http::write(socket, response);
        co_return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    conn = irods::s3::get_connection(irods_username);

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(*conn, url.segments()); bucket.has_value()) {
        path = bucket.value();
        path = irods::s3::finish_path(path, url.segments());
    }
    else {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::not_found);
        std::cerr << "Could not find bucket" << std::endl;
        beast::http::write(socket, response);

        co_return;
    }
    std::cout << "Requested " << path << std::endl;

    try {
        if (fs::client::exists(*conn, path) && not fs::client::is_collection(*conn, path)) {
            beast::http::response<beast::http::empty_body> response;
            if (fs::client::remove(*conn, path, experimental::filesystem::remove_options::no_trash)) {
                std::cerr << "Supposedly " << path << " doesn't exist anymore" << std::endl;
                response.result(beast::http::status::ok);
            }
            else {
                response.result(beast::http::status::forbidden);
            }
            beast::http::write(socket, response);
        }
        else {
            std::cerr << "Could not find file" << path << std::endl;
        }
    }
    catch (irods::exception& e) {
        beast::http::response<beast::http::empty_body> response;
        std::cout << "Exception! in the deleteobject" << std::endl;
        response.result(beast::http::status::forbidden);

        switch (e.code()) {
            case USER_ACCESS_DENIED:
            case CAT_NO_ACCESS_PERMISSION:
                response.result(beast::http::status::forbidden);
                break;
            default:
                // Relevant ones here are SYS_INVALID_INPUT_PARAM,
                // CAT_NOT_A_DATA_OBJ_AND_NOT_A_COLLECTION,
                // SAME_SRC_DEST_PATHS_ERR
                response.result(beast::http::status::internal_server_error);
                break;
        }

        beast::http::write(socket, response);
        co_return;
    }
    catch (...) {
        std::cout << boost::stacktrace::stacktrace() << std::endl;
    }
    co_return;
}
