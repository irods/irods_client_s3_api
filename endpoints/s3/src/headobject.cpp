#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

#include <irods/irods_exception.hpp>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace log = irods::http::log;

const static std::string_view date_format{"{:%a, %d %b %Y %H:%M:%S GMT}"};

void irods::s3::actions::handle_headobject(
    irods::http::session_pointer_type session_ptr,
    boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
    const boost::urls::url_view& url)
{
    beast::http::response<beast::http::empty_body> response;
    response.result(beast::http::status::forbidden);

    try {
        auto irods_username = irods::s3::authentication::authenticates(parser, url);

        if (!irods_username) {
            response.result(beast::http::status::forbidden);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response)); 
            return;
       }

       auto conn = irods::get_connection(*irods_username); 

       fs::path path;
       if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
           path = bucket.value();
           path = irods::s3::finish_path(path, url.segments());
       }
       else {
           log::error("Failed to resolve bucket");
           response.result(beast::http::status::forbidden);
           log::debug("{}: returned {}", __FUNCTION__, response.reason());
           session_ptr->send(std::move(response)); 
           return;
       }
       bool can_see = false;

       if (fs::client::exists(conn, path)) {

           // Ideally in the future exists won't return true on things that you're not allowed to see,
           // But until then, check for any mentioned permission.
           auto all_permissions = fs::client::status(conn, path).permissions();
           for (const auto& i : all_permissions) {
               if (i.name == *irods_username) {
                   can_see = true;
               }
           }

           if (!can_see) {
               response.result(boost::beast::http::status::forbidden);
               log::debug("{}: returned {}", __FUNCTION__, response.reason());
               session_ptr->send(std::move(response)); 
               return;
           }

           // change response body to string_body
           response.result(boost::beast::http::status::ok);
           std::string length_field = std::to_string(irods::experimental::filesystem::client::data_object_size(conn, path));
           response.insert(beast::http::field::content_length, length_field);

           auto last_write_time__time_point = irods::experimental::filesystem::client::last_write_time(conn, path);
           std::time_t last_write_time__time_t = std::chrono::system_clock::to_time_t(last_write_time__time_point);
           std::string last_write_time__str = irods::s3::api::common_routines::convert_time_t_to_str(last_write_time__time_t, date_format);
           response.insert(beast::http::field::last_modified, last_write_time__str);
           log::debug("{}: returned {}", __FUNCTION__, response.reason());
           session_ptr->send(std::move(response)); 
           return;
       } else {
           response.result(boost::beast::http::status::not_found);
           log::debug("{}: returned {}", __FUNCTION__, response.reason());
           session_ptr->send(std::move(response)); 
           return;
           /*return irods::s3::api::common_routines::send_error_response(
                   session_ptr,
                   boost::beast::http::status::not_found,
                   "NoSuchKey",
                   "Object does not exist",
                   url.path(),
                   __FUNCTION__);*/
       }
    }
    catch (std::system_error& e) {
        log::error("{}: {}", __FUNCTION__, e.what());
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
   
    log::debug("{}: returned {}", __FUNCTION__, response.reason());
    session_ptr->send(std::move(response)); 
    return;
}
