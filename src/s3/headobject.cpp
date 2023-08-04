//
// Created by violet on 1/28/23.
//
#include "./s3_api.hpp"
#include "../authentication.hpp"
#include "../bucket.hpp"

#include <irods/irods_exception.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

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
        if (!irods::s3::authentication::authenticates(*thing, parser, url)) {
            response.result(beast::http::status::forbidden);
        }
        else {
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
            }
            else {
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

#if 0
    // mc client responses with:
    //
    //      mc: <ERROR> Unable to validate source `ours3/the-bucket/foo`: Last-Modified time format is invalid, failed with unable to parse  in any of the input formats: [Mon, 2 Jan 2006 15:04:05 GMT Mon, _2 Jan 2006 15:04:05 GMT Mon, _2 Jan 06 15:04:05 GMT
    //
    // We need to send more information in the response. We're likely missing several headers.
    // At the moment, we're sending a very generic response to the client.
    response.set("Last-Modified", "Mon, 2 Jan 2007 15:04:05 GMT");
    response.set("Content-Length", "20");
#endif
    beast::http::write(socket, response);

    co_return;
}
