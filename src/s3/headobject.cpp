//
// Created by violet on 1/28/23.
//
#include "./s3_api.hpp"
#include "../authentication.hpp"
#include "../bucket.hpp"
#include "../common_routines.hpp"

#include <irods/irods_exception.hpp>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

static const std::string date_format{"{:%a, %d %b %Y %H:%M:%S GMT}"};

boost::asio::awaitable<void> irods::s3::actions::handle_headobject(
    boost::asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    auto thing = irods::s3::get_connection();
    beast::http::response<beast::http::empty_body> response;
    response.result(beast::http::status::forbidden);
    // TODO I think the operations in this block can be unwrapped safely
    try {
        auto irods_username = irods::s3::authentication::authenticates(*thing, parser, url);

        if (!irods_username) {
            response.result(beast::http::status::forbidden);
        }
        else {
            // Reconnect to the iRODS server as the target user.
            // The rodsadmin account from the config file will act as the proxy for the user.
            thing = irods::s3::get_connection(irods_username);

            fs::path path;
            if (auto bucket = irods::s3::resolve_bucket(*thing, url.segments()); bucket.has_value()) {
                path = bucket.value();
                path = irods::s3::finish_path(path, url.segments());
            }
            else {
                std::cout << "Failed to resolve bucket" << std::endl;
            }
            bool can_see = false;
            std::cout << "Tryna perm" << std::endl;

            if (fs::client::exists(*thing, path)) {
                std::cout << "Found it?" << std::endl;

                // Ideally in the future exists won't return true on things that you're not allowed to see,
                // But until then, check for any mentioned permission.
                auto all_permissions = fs::client::status(*thing, path).permissions();
                for (const auto& i : all_permissions) {
                    if (i.name == thing->clientUser.userName) {
                        can_see = true;
                    }
                }
                response.result(can_see ? boost::beast::http::status::ok : boost::beast::http::status::forbidden);
                std::cout << response.result() << std::endl;

                std::string length_field = std::to_string(irods::experimental::filesystem::client::data_object_size(*thing, path));
                response.insert(beast::http::field::content_length, length_field);

                auto last_write_time__time_point = irods::experimental::filesystem::client::last_write_time(*thing, path);
                std::time_t last_write_time__time_t = std::chrono::system_clock::to_time_t(last_write_time__time_point);
                std::string last_write_time__str = irods::s3::api::common_routines::convert_time_t_to_str(last_write_time__time_t, date_format);
                response.insert(beast::http::field::last_modified, last_write_time__str);

            } else {
                response.result(boost::beast::http::status::not_found);
            }
        }
    }
    catch (std::system_error& e) {
        std::cout << "huh" << std::endl;
        std::cout << e.what() << std::endl;
        switch (e.code().value()) {
            case USER_ACCESS_DENIED:
            case CAT_NO_ACCESS_PERMISSION:
                response.result(beast::http::status::forbidden);
                break;
        }
    }

    beast::http::write(socket, response);

    co_return;
}
