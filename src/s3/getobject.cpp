#include "s3_api.hpp"

#include "../connection.hpp"
#include "../configuration.hpp"
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
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

asio::awaitable<void> irods::s3::actions::handle_getobject(
    asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    auto thing = irods::s3::get_connection();

    // Permission verification stuff should go roughly here.

    auto irods_username = irods::s3::authentication::authenticates(*thing, parser, url);
    if (!irods_username) {
        std::cout<<"Authentication failed"<<std::endl;
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::forbidden);
        beast::http::write(socket, response);
        co_return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    thing = irods::s3::get_connection(irods_username);

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(*thing, url.segments()); bucket.has_value()) {
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

    // read the range header if it exists
    // Note:  We are only implementing range headers in the format range: bytes=<start>-[end]
    std::size_t range_start = 0;
    std::size_t range_end = 0;
    auto range_header = parser.get().find("range");
    if (range_header != parser.get().end()) {
        if (range_header->value().starts_with("bytes=")) {
            std::string range = range_header->value().substr(6);

            std::vector<std::string> range_parts;
            boost::split(range_parts, range, boost::is_any_of("-"));

            if (range_parts.size() != 2) {
                std::cerr<< "The provided range format has not been implemented." << std::endl;
                beast::http::response<beast::http::empty_body> response;
                response.result(beast::http::status::not_implemented);
                beast::http::write(socket, response);
                co_return;
            }

            try {
                range_start = boost::lexical_cast<std::size_t>(range_parts[0]);
                if (!range_parts[1].empty()) {
                    range_end = boost::lexical_cast<std::size_t>(range_parts[1]);
                }
            }
            catch (const boost::bad_lexical_cast&) {
                std::cerr<< "Could not cast the start or end range to a size_t." << std::endl;
                beast::http::response<beast::http::empty_body> response;
                response.result(beast::http::status::not_implemented);
                beast::http::write(socket, response);
                co_return;
            }

        }
        else {
            std::cerr<< "The provided range format has not been implemented - does not begin with \"bytes=\"." << std::endl;
            beast::http::response<beast::http::empty_body> response;
            response.result(beast::http::status::not_implemented);
            beast::http::write(socket, response);
            co_return;
        }
    } 

    try {
        if (fs::client::exists(*thing, path)) {
            std::cout << "Trying to write file" << std::endl;
            beast::http::response<beast::http::buffer_body> response;
            beast::http::response_serializer<beast::http::buffer_body> serializer{response};

            uint64_t write_buffer_size = irods::s3::get_get_object_buffer_size_in_bytes();
            std::cout << "write buffer size = " << write_buffer_size << std::endl;
            std::vector<char> buf_vector(write_buffer_size);

            auto file_size = irods::experimental::filesystem::client::data_object_size(*thing, path);
            if (range_end == 0 || range_end > file_size - 1) {
                range_end = file_size - 1;
            }
            auto content_length = range_end - range_start + 1;  // ranges are inclusive

            std::string length_field =
                std::to_string(content_length);
            response.insert(beast::http::field::content_length, length_field);
            auto md5 = irods::experimental::filesystem::client::data_object_checksum(*thing, path);
            response.insert("Content-MD5", md5);

            beast::error_code ec;
            irods::experimental::io::client::default_transport xtrans{*thing};
            irods::experimental::io::idstream d{
                xtrans, path, irods::experimental::io::root_resource_name{irods::s3::get_resource()}};

            // seek to the start range
            d.seekg(range_start);
            size_t offset = range_start;

            if (d.fail() || d.bad()) {
                std::cout << "Fail/badbit set" << std::endl;
                response.result(beast::http::status::forbidden);
                response.body().more = false;
                beast::http::write(socket, response);
                co_return;
            }
            beast::http::write_header(socket, serializer);
            std::streampos current, size;
            while (d.good()) {
                response.result(beast::http::status::ok);

                // Determine the length we need to read which is the smaller
                // of the write_buffer_size or the bytes to the end of the range.
                // Note that ranges are inclusive which is why the +1's exist. 
                std::size_t read_length
                    = write_buffer_size < range_end + 1 - offset 
                    ? write_buffer_size 
                    : range_end + 1 - offset;

                d.read(buf_vector.data(), read_length);
                current = d.gcount();
                offset += current;
                size += current;
                response.body().data = buf_vector.data();
                response.body().size = current;
                if (d.bad()) {
                    std::cerr << "Weird error?" << std::endl;
                    exit(12);
                }
                try {
                    beast::http::write(socket, serializer);
                }
                catch (boost::system::system_error& e) {
                    if (e.code() != beast::http::error::need_buffer) {
                        std::cout << "System error when writing bytes to socket during GetObject - "
                            << e.code().message() << "[" << e.code() << "]" << std::endl;
                        throw e;
                    }
                    else {
                        // It would be nice if we could figure out something a bit more
                        // semantic than catching an exception
                    }
                }

                // If we have now read beyond the range_end then we are done.  Break out.
                if (offset > range_end) {
                    break;
                }
            }
            response.body().size = d.gcount();
            response.body().more = false;
            beast::http::write(socket, serializer);
        }
        else {
            beast::http::response<beast::http::empty_body> response;
            response.result(beast::http::status::not_found);
            std::cerr << "Could not find file" << std::endl;
            beast::http::write(socket, response);
        }
    }
    catch (irods::exception& e) {
        beast::http::response<beast::http::empty_body> response;
        std::cout << "Exception! in the getobject" << std::endl;
        response.result(beast::http::status::forbidden);

        switch (e.code()) {
            case USER_ACCESS_DENIED:
            case CAT_NO_ACCESS_PERMISSION:
                response.result(beast::http::status::forbidden);
                break;
            default:
                response.result(beast::http::status::internal_server_error);
                break;
        }

        beast::http::write(socket, response);
        co_return;
    }
    catch (std::exception& e) {
        std::cout << boost::stacktrace::stacktrace() << std::endl;
        std::cout << "error! " << e.what() << std::endl;
    }

    beast::http::response<beast::http::dynamic_body> response;

    co_return;
}
