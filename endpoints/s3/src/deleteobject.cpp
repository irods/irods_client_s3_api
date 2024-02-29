#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

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
namespace logging = irods::http::logging;

void irods::s3::actions::handle_deleteobject(
        irods::http::session_pointer_type session_ptr,
        boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
        const boost::urls::url_view& url)
{
    beast::http::response<beast::http::empty_body> response;

    // Permission verification stuff should go roughly here.

    auto irods_username = irods::s3::authentication::authenticates(parser, url);
    if (!irods_username) {
        response.result(beast::http::status::forbidden);
        logging::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    auto conn = irods::get_connection(*irods_username);

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
        path = bucket.value();
        path = irods::s3::finish_path(path, url.segments());
    }
    else {
        response.result(beast::http::status::not_found);
        logging::debug("{}: Could not find bucket", __FUNCTION__);
        logging::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }
    logging::debug("{}: Requested to delete {}", __FUNCTION__, path.string());

    try {
        if (fs::client::exists(conn, path) && not fs::client::is_collection(conn, path)) {
            if (fs::client::remove(conn, path, experimental::filesystem::remove_options::no_trash)) {
                logging::debug("{}: Remove {} successful", __FUNCTION__, path.string());
                response.result(beast::http::status::ok);
            }
            else {
                response.result(beast::http::status::forbidden);
            }
            logging::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response)); 
            return;
        }
        else {
            logging::debug("{}: Could not find file {}", __FUNCTION__, path.string());
            response.result(beast::http::status::not_found);
            logging::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response)); 
            return;
        }
    }
    catch (irods::exception& e) {
        beast::http::response<beast::http::empty_body> response;
        logging::debug("{}: Exception encountered", __FUNCTION__);

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
        logging::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }
    catch (...) {
        response.result(beast::http::status::not_found);
        logging::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
    }
}
