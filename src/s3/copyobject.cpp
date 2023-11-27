#include "s3_api.hpp"
#include "../authentication.hpp"
#include "../connection.hpp"
#include "../bucket.hpp"
#include "../types.hpp"
#include <boost/beast.hpp>
#include <boost/property_tree/ptree_fwd.hpp>

#include <irods/irods_exception.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

boost::asio::awaitable<void> irods::s3::actions::handle_copyobject(
    boost::asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    auto conn = irods::s3::get_connection();
    std::cerr << "I'm about to authenticate for copying?" << std::endl;

    auto irods_username = irods::s3::authentication::authenticates(*conn, parser, url);
    if (!irods_username) {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::forbidden);
        beast::http::write(socket, response);
        co_return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    conn= irods::s3::get_connection(irods_username);

    auto url2 = boost::urls::url(parser.get()["x-amz-copy-source"]);
    fs::path destination_path, source_path;
    std::cerr << "We're starting a copy" << std::endl;
    bool succeeds = false;
    if (auto bucket = irods::s3::resolve_bucket(*conn, url2.segments()); bucket.has_value()) {
        source_path = irods::s3::finish_path(bucket.value(), url2.segments());
    }
    else {
        std::cerr << "Could not locate source path" << std::endl;
    }
    std::cerr << "We've gotten past the source" << std::endl;
    if (auto bucket = irods::s3::resolve_bucket(*conn, url.segments()); bucket.has_value()) {
        destination_path = irods::s3::finish_path(bucket.value(), url.segments());
    }
    else {
        std::cerr << "Could not locate destination path" << std::endl;
    }
    std::cerr << "We've gotten past the destination" << std::endl;
    if (source_path.empty() || destination_path.empty()) {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::not_found);
        beast::http::write(socket, response);
        co_return;
    }
    std::cout << "We've gotten to the copying?" << std::endl;
    try {
        fs::client::copy(*conn, source_path, destination_path, fs::copy_options::overwrite_existing);
    }
    catch (irods::experimental::filesystem::filesystem_error& ex) {
        beast::http::response<beast::http::empty_body> response;
        switch (ex.code().value()) {
                // It's funny that it uses iRODS codes here in what seems likely to have been meant for
                // things like ENOFILE or EPERM
            case USER_ACCESS_DENIED:
            case CAT_NO_ACCESS_PERMISSION:
                response.result(beast::http::status::forbidden);
                break;
            default:
                std::cerr << ex.what() << std::endl;

                response.result(beast::http::status::internal_server_error);
                break;
        }
        beast::http::write(socket, response);
        co_return;
    }
    catch (...) {
        std::cerr << "Something happened" << std::endl;
    }
    std::cerr << "Copied object!" << std::endl;
    // We don't have real etags, so using the md5 here would be confusing, as it would match any number of distinct
    // objects The most accurate representation of an Etag that I am aware of that we can get "for free" is using the
    // md5 sum appended to the path of the object. This makes it both content-sensitive and location sensitive.
    beast::http::response<beast::http::string_body> response;
    response.body() = "<CopyObjectResult/>";
    beast::http::write(socket, response);
    co_return;
}
