#include "./s3_api.hpp"
#include "../connection.hpp"

#include "../authentication.hpp"
#include "../bucket.hpp"
#include "../configuration.hpp"

#include <boost/beast/core/error.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>

#include <iostream>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;

#pragma clang diagnostic push
#pragma ide diagnostic ignored "UnusedValue"
asio::awaitable<void> irods::s3::actions::handle_putobject(
    asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    boost::beast::error_code ec;
    connection_handle connection = get_connection();
    auto& parser_message = parser.get();

    // Look for the header that MinIO sends for chunked data.  If it exists we
    // have to parse chunks ourselves.
    bool special_chunked_header = false;
    auto header = parser_message.find("x-Amz-Content-Sha256");
    if (header != parser_message.end() && header->value() == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
        special_chunked_header = true;
    }
    std::cout << "special_chunked_header: " << special_chunked_header << std::endl;

    // See if we have chunked set.  If so turn off special chunked header flag as the
    // parser will handle it.
    bool chunked_flag = false;
    if (parser_message[beast::http::field::transfer_encoding] == "chunked") {
        special_chunked_header = false;
        chunked_flag = true;
    }

    // If chunked_flag is false, make sure we have Content-Length or
    // we will not be able to parse the response as the parser will return
    // immediately.  If we have special_chunked header we still need
    // the Content-Length.
    if (!chunked_flag) {
        header = parser_message.find("Content-Length");
        if (header == parser_message.end()) {
            beast::http::response<boost::beast::http::empty_body> response;
            response.result(boost::beast::http::status::bad_request);
            beast::http::write(socket, response);
            std::cout << "Neither Content-Length nor chunked mode were set." << std::endl;
            co_return;
        }
    }

    // Authenticate
    auto irods_username = irods::s3::authentication::authenticates(*connection, parser, url);

    if (!irods_username) {
        beast::http::response<boost::beast::http::empty_body> response;
        response.result(boost::beast::http::status::forbidden);
        beast::http::write(socket, response);
        std::cout << "Failed to auth" << std::endl;
        co_return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    connection = irods::s3::get_connection(irods_username);

    if (parser_message[beast::http::field::expect] == "100-continue") {
        beast::http::response<beast::http::empty_body> resp;
        resp.version(11);
        resp.result(beast::http::status::continue_);
        resp.set(beast::http::field::server, parser_message["Host"]);
        beast::http::write(socket, resp, ec);
        std::cout << "Sent 100-continue" << std::endl;
    }

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(*connection, url.segments()); bucket.has_value()) {
        path = std::move(bucket.value());
        path = irods::s3::finish_path(path, url.segments());
    }
    else {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::not_found);
        std::cerr << "No bucket found" << std::endl;
        beast::http::write(socket, response);
        co_return;
    }
    std::cout << "Path: [" << path << "]" << std::endl;
    {
        beast::flat_buffer buffer;
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::ok);

        irods::experimental::io::client::default_transport xtrans{*connection};

        fs::client::create_collections(*connection, path.parent_path());
        irods::experimental::io::odstream d{
            xtrans, path, irods::experimental::io::root_resource_name{irods::s3::get_resource()}, std::ios_base::out};

        if (!d.is_open()) {
            beast::http::response<beast::http::empty_body> response;
            response.result(beast::http::status::internal_server_error);
            std::cerr << "Failed to open dstream" << std::endl;
            beast::http::write(socket, response);
            co_return;
        }

        uint64_t read_buffer_size = irods::s3::get_put_object_buffer_size_in_bytes();
        uint64_t max_read_buffer_size = irods::s3::get_put_object_max_buffer_size_in_bytes();
        std::cout << "read buffer size = " << read_buffer_size << std::endl;
        std::cout << "max read buffer size = " << max_read_buffer_size << std::endl;
        std::vector<char> buf_vector(read_buffer_size);
        parser_message.body().data = buf_vector.data();
        parser_message.body().size = read_buffer_size; 

        response.set("Etag", path.c_str());
        response.set("Connection", "close");

        if (special_chunked_header) {
            std::cout << "read buffer size = " << read_buffer_size << std::endl;


            boost::beast::error_code ec;

            enum class parsing_state {
                header_begin, header_continue, body, end_of_chunk, parsing_done, parsing_error
            };

            parsing_state current_state = parsing_state::header_begin;
            std::string the_bytes;

            size_t chunk_size = 0;

            // While we have more data to be read from the socket into the_bytes or
            // we haven't exhausted the_bytes.
            while (!parser.is_done() || !the_bytes.empty()) {

                // check to see if we are done parsing the chunks
                if (current_state == parsing_state::parsing_done || current_state == parsing_state::parsing_error) {
                    break;
                }

                parser_message.body().data = buf_vector.data();
                parser_message.body().size = read_buffer_size;
                
                if (!parser.is_done()) {
                    // The eager option instructs the parser to continue reading the buffer once it has completed a
                    // structured element (header, chunk header, chunk body). Since we are handling the parsing ourself,
                    // we want the parser to give us as much as is available.
                    parser.eager(true);
                    co_await beast::http::read_some(socket, buffer, parser, ec);

                    // The need_buffer exception is an indication that the current buffer
                    // is not large enough for the parser to handle the request.  Double
                    // the buffer size up to a maximum allowed buffer size.
                    if(ec == beast::http::error::need_buffer) {
                        read_buffer_size *= 2;
                        if (read_buffer_size > max_read_buffer_size) {
                            read_buffer_size = max_read_buffer_size;
                        }
                        buf_vector.resize(read_buffer_size);
                        std::cout << "read buffer size updated to " << read_buffer_size << std::endl;
                        ec = {};
                    }
                    if(ec) {
                        beast::http::response<beast::http::empty_body> response;
                        response.result(beast::http::status::internal_server_error);
                        std::cerr << "Error reading data" << std::endl;
                        beast::http::write(socket, response);
                        co_return;
                    }
                }

                size_t read_bytes = read_buffer_size - parser_message.body().size;
                the_bytes.append(buf_vector.data(), read_bytes);

                switch (current_state) {
                    case parsing_state::header_begin:
                    {
                        // Chunk headers can be of the following forms:
                        // 1. With extensions: <hex>;extension1=extension1value;extension2=extension2value\r\n
                        // 2. Without extensions: <hex>\r\n
                        
                        // See if it is of form 1.
                        size_t colon_location = the_bytes.find (";");
                        if (colon_location == std::string::npos) {

                            // Not form 1.  See if it is form 2.
                            size_t newline_location = the_bytes.find("\r\n");
                            if (newline_location != std::string::npos) {
                                std::string chunk_size_str = the_bytes.substr(0, newline_location);
                                size_t hex_digits_parsed = 0;
                                try {
                                    chunk_size = stoull(chunk_size_str, &hex_digits_parsed, 16);
                                } catch (std::invalid_argument& e) {
                                    hex_digits_parsed = 0;
                                }

                                if (hex_digits_parsed == chunk_size_str.length()) {
                                    // eat the bytes up to and including \r\n 
                                    the_bytes = the_bytes.substr(newline_location+2);
                                    if (chunk_size == 0) {
                                        current_state = parsing_state::parsing_done;
                                    } else {
                                        current_state = parsing_state::body;
                                    }
                                } else {
                                    std::cout << "Bad chunk size: " << chunk_size_str << std::endl;
                                    current_state = parsing_state::parsing_error;
                                }
                            }   
                        } else {
                            std::string chunk_size_str = the_bytes.substr(0, colon_location);
                            size_t hex_digits_parsed = 0;
                            try {
                               chunk_size = stoull(chunk_size_str, &hex_digits_parsed, 16);
                            } catch (std::invalid_argument& e) {
                                hex_digits_parsed = 0;
                            }
                            if (hex_digits_parsed == chunk_size_str.length()) {
                                // eat the bytes up to and including colon
                                the_bytes = the_bytes.substr(colon_location+1);
                                current_state = parsing_state::header_continue;
                            } else {
                                std::cout << "Bad chunk size: " << chunk_size_str << std::endl;
                                current_state = parsing_state::parsing_error;
                            }
                        }
                        break;
                    }
                    case parsing_state::header_continue:
                    {
                        // move beyond the newline 
                        size_t newline_location = the_bytes.find("\r\n");

                        // reset string stream and set it to after the \r\n
                        if (newline_location != std::string::npos) {
                            the_bytes = the_bytes.substr(newline_location+2);
                            if (chunk_size == 0) {
                                current_state = parsing_state::parsing_done;
                            } else {
                                current_state = parsing_state::body;
                            }
                        }
                        break;
                    }
                    case parsing_state::body:
                    {
                        size_t ss_size = the_bytes.length();

                        // if we have the full chunk, handle it otherwise continue
                        // until we do
                        if (ss_size >= chunk_size) {
                            std::string body = the_bytes.substr(0, chunk_size);

                            try {
                                d.write(body.c_str(), body.length());
                            }
                            catch (std::exception& e) {
                                std::cout << e.what() << std::endl;
                            }

                            // reset string stream and set it to after the \r\n
                            the_bytes = the_bytes.substr(chunk_size);
                            current_state = parsing_state::end_of_chunk;
                        }
                        break;
                    }
                    case parsing_state::end_of_chunk:
                    {
                        size_t newline_location = the_bytes.find("\r\n");
                        if (newline_location != 0) {
                            std::cout << "Invalid chunk end sequence" << std::endl;
                            current_state = parsing_state::parsing_error;
                        } else {
                            // remove \r\n and go to next chunk
                            the_bytes = the_bytes.substr(2);
                            current_state = parsing_state::header_begin;
                        }
                        break;
                    }
                    default:
                        break;

                };

            }

            if (current_state == parsing_state::parsing_error) {
                beast::http::response<boost::beast::http::empty_body> response;
                response.result(boost::beast::http::status::bad_request);
                beast::http::write(socket, response);
                std::cout << "Error parsing chunked body." << std::endl;
                co_return;
            }

        } else {
            // Let boost::beast::parser handle the body
            while (!parser.is_done()) {
                
                parser_message.body().data = buf_vector.data();
                parser_message.body().size = read_buffer_size;
                co_await beast::http::read_some(socket, buffer, parser, ec);
                size_t read_bytes = read_buffer_size - parser_message.body().size;

                std::string the_bytes{buf_vector.data(), read_bytes};

                // The need_buffer exception is an indication that the current buffer
                // is not large enough for the parser to handle the request.  Double
                // the buffer size up to a maximum allowed buffer size.
                if (ec == beast::http::error::need_buffer) {
                    if (read_buffer_size < max_read_buffer_size) {
                        read_buffer_size *= 2;
                        if (read_buffer_size > max_read_buffer_size) {
                            read_buffer_size = max_read_buffer_size;
                        }
                        buf_vector.resize(read_buffer_size);
                        std::cout << "read buffer size updated to " << read_buffer_size << std::endl;
                        ec = {};
                    }
                }

                if (ec) {
                    std::cout << ec.what() << std::endl;
                    co_return;
                }

                try {
                    d.write((char*) buf_vector.data(), read_bytes);
                }
                catch (std::exception& e) {
                    std::cout << e.what() << std::endl;
                }

             }
        }

        beast::http::write(socket, response, ec);
        if (ec) {
            std::cout << "Error! " << ec.what() << std::endl;
        }
        std::cout << "wrote response" << std::endl;
    }
    co_return;
}
#pragma clang diagnostic pop
