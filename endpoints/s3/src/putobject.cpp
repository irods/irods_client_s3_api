#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/configuration.hpp"
#include "irods/private/s3_api/globals.hpp"

#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>

#include <boost/beast/core/error.hpp>

#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>

#include <iostream>
#include <vector>
#include <fstream>
#include <regex>
#include <memory>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace log = irods::http::log;


static std::regex upload_id_pattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

namespace {
    enum class parsing_state {
       header_begin, header_continue, body, end_of_chunk, parsing_done, parsing_error
    };
}


void manually_parse_chunked_body_write_to_irods_in_background(
    irods::http::session_pointer_type session_ptr,
    beast::http::response<beast::http::empty_body>& response_,
    std::shared_ptr<beast::http::request_parser<boost::beast::http::buffer_body>> parser,
    uint64_t read_buffer_size,
    std::shared_ptr<std::ofstream> ofs,
    std::shared_ptr<irods::experimental::io::odstream> d,
    bool upload_part,
    parsing_state current_state,
    size_t chunk_size,
    const std::string& parsing_buffer_string,
    const std::string func);

void beast_parse_body_write_to_irods_in_background(
    irods::http::session_pointer_type session_ptr,
    beast::http::response<beast::http::empty_body>& response_,
    std::shared_ptr<beast::http::request_parser<boost::beast::http::buffer_body>> parser,
    uint64_t read_buffer_size,
    std::shared_ptr<std::ofstream> ofs,
    std::shared_ptr<irods::experimental::io::odstream> d,
    bool upload_part,
    uint64_t total_bytes_read,
    const::std::string part_number,
    const std::string func);

void irods::s3::actions::handle_putobject(
    irods::http::session_pointer_type session_ptr,
    beast::http::request_parser<boost::beast::http::empty_body>& empty_body_parser,
    const boost::urls::url_view& url)
{
    using irods_default_transport = irods::experimental::io::client::default_transport;
    using irods_connection = irods::http::connection_facade;

    beast::http::response<beast::http::empty_body> response;

    // Authenticate
    auto irods_username = irods::s3::authentication::authenticates(empty_body_parser, url);

    if (!irods_username) {
        log::error("{}: Failed to authenticate.", __FUNCTION__);
        response.result(beast::http::status::forbidden);
        log::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }

    // wrap the connection in a shared pointer as the object must last longer than this routine
    std::shared_ptr<irods_connection> conn = std::make_shared<irods_connection>(irods::get_connection(*irods_username)); 

    // change the parser to a buffer_body parser and wrap in a shared_ptr
    std::shared_ptr parser = std::make_shared<beast::http::request_parser<boost::beast::http::buffer_body>>(std::move(empty_body_parser));
    auto& parser_message = parser->get();

    // Look for the header that MinIO sends for chunked data.  If it exists we
    // have to parse chunks ourselves.
    bool special_chunked_header = false;
    auto header = parser_message.find("x-Amz-Content-Sha256");
    if (header != parser_message.end() && header->value() == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
        special_chunked_header = true;
    }
    log::debug("{} special_chunk_header: {}", __FUNCTION__, special_chunked_header);

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
            log::error("{} Neither Content-Length nor chunked mode were set.", __FUNCTION__);
            response.result(boost::beast::http::status::bad_request);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response));
            return;
        }
    }

    if (parser_message[beast::http::field::expect] == "100-continue") {
        response.version(11);
        response.result(beast::http::status::continue_);
        response.set(beast::http::field::server, parser_message["Host"]);
        session_ptr->send(std::move(response)); 
        log::debug("{}: Sent 100-continue", __FUNCTION__);
    }

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
        path = std::move(bucket.value());
        path = irods::s3::finish_path(path, url.segments());
    }
    else {
        log::error("{}: Failed to resolve bucket", __FUNCTION__);
        response.result(beast::http::status::not_found);
        log::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }
    log::debug("{}: Path [{}]", __FUNCTION__, path.string());

    // check to see if this is a part upload
    bool upload_part = false;
    std::string part_number;
    std::string upload_id;
    std::string upload_part_filename;
    if (const auto part_number_param = url.params().find("partNumber"); part_number_param != url.params().end()) {
        part_number = (*part_number_param).value;
    }
    if (const auto upload_id_param = url.params().find("uploadId"); upload_id_param != url.params().end()) {
        upload_id = (*upload_id_param).value;
    }

    if (!part_number.empty() || !upload_id.empty()) {
        // either partNumber or uploadId provided
        upload_part = true;
        if (part_number.empty()) {
            log::error("{}: UploadPart detected but partNumber was not provided.", __FUNCTION__);
            response.result(beast::http::status::bad_request);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response));
            return;
        } else if (upload_id.empty()) {
            log::error("{}: UploadPart detected but upload_id was not provided.", __FUNCTION__);
            response.result(beast::http::status::bad_request);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response));
            return;
        } else if (!std::regex_match(upload_id, upload_id_pattern)) {
            log::error("{}: Upload ID {} was not in expected format.", __FUNCTION__, upload_id);
            response.result(beast::http::status::bad_request);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response)); 
            return;
        }

        // get the base location for the part files
        const nlohmann::json& config = irods::http::globals::configuration();
        std::string part_file_location = config.value(
                nlohmann::json::json_pointer{"/s3_server/location_part_upload_files"}, ".");

        // the current part file full path
        upload_part_filename = part_file_location + "/" + upload_id + "." + part_number;
        log::debug("{}: UploadPart detected.  partNumber={} uploadId={}", __FUNCTION__, part_number, upload_id);
    }

    fs::client::create_collections(*conn, path.parent_path());

    // create an output file stream to iRODS - wrap all structs in shared pointers
    // since these objects will persist than the current routine
    std::shared_ptr<irods_default_transport> xtrans = std::make_shared<irods_default_transport>(*conn);
    std::shared_ptr<irods::experimental::io::odstream> d = std::make_shared<irods::experimental::io::odstream>();

    // posix file stream for writing parts locally - wrapped in a shared pointer
    // since this will persist longer than the current routine
    std::shared_ptr<std::ofstream> ofs = std::make_shared<std::ofstream>();

    if (upload_part) {
        ofs->open(upload_part_filename, std::ofstream::out);
        // TODO fs::resize_file(p, content_length);
        if (!ofs->is_open()) {
            log::error("{}: Failed to open stream for writing part", __FUNCTION__);
            response.result(beast::http::status::internal_server_error);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response));
            return;
        }
    } else {
        d->open(*xtrans, std::move(path), irods::experimental::io::root_resource_name{irods::s3::get_resource()}, std::ios_base::out);
        if (!d->is_open()) {
            log::error("{}: Failed to open dstream to iRODS", __FUNCTION__);
            response.result(beast::http::status::internal_server_error);
            log::debug("{}: returned {}", __FUNCTION__, response.reason());
            session_ptr->send(std::move(response));
            return;
        }
    }

    uint64_t read_buffer_size = irods::s3::get_put_object_buffer_size_in_bytes();
    log::debug("{}: read_buffer_size={}", __FUNCTION__, read_buffer_size);

    std::vector<char> buf_vector(read_buffer_size);
    parser_message.body().data = buf_vector.data();
    parser_message.body().size = read_buffer_size; 

    response.set("Etag", path.c_str());
    response.set("Connection", "close");
    response.keep_alive(parser_message.keep_alive());

    if (special_chunked_header) {

        // The eager option instructs the parser to continue reading the buffer once it has completed a
        // structured element (header, chunk header, chunk body). Since we are handling the parsing ourself,
        // we want the parser to give us as much as is available.
        parser->eager(true);

        parsing_state current_state = parsing_state::header_begin;

        // This is a string that holds input bytes temporarily as they are being read
        // from the stream.  This chunk parser will only read more bytes into this
        // when necessary to continue parsing.  Once bytes are no longer needed they are
        // discarded from this variable.
        std::string parsing_buffer_string;
        size_t chunk_size = -1;

        manually_parse_chunked_body_write_to_irods_in_background(
                session_ptr,
                response,
                parser,
                read_buffer_size,
                ofs,
                d,
                upload_part,
                current_state,
                chunk_size,
                parsing_buffer_string,
                __FUNCTION__);

    } else {
        // Let boost::beast::parser handle the body
        uint64_t total_bytes_read = 0;
        beast_parse_body_write_to_irods_in_background(
                session_ptr,
                response,
                parser,
                read_buffer_size,
                ofs,
                d,
                upload_part,
                total_bytes_read,
                part_number,
                __FUNCTION__);
    }

    return;
}

void manually_parse_chunked_body_write_to_irods_in_background(
    irods::http::session_pointer_type session_ptr,
    beast::http::response<beast::http::empty_body>& response_,
    std::shared_ptr<beast::http::request_parser<boost::beast::http::buffer_body>> parser,
    uint64_t read_buffer_size,
    std::shared_ptr<std::ofstream> ofs,
    std::shared_ptr<irods::experimental::io::odstream> d,
    bool upload_part,
    parsing_state current_state,
    size_t chunk_size,
    const std::string& parsing_buffer_string_,
    const std::string func)
{
    irods::http::globals::background_task([session_ptr,
        response = std::move(response_),
        parser,
        read_buffer_size,
        ofs,
        d,
        upload_part,
        current_state,
        chunk_size,
        parsing_buffer_string = std::move(parsing_buffer_string_),
        func]() mutable {

        boost::beast::error_code ec;
        auto& parser_message = parser->get();

        std::vector<char> buf_vector(read_buffer_size);
        parser_message.body().data = buf_vector.data();
        parser_message.body().size = read_buffer_size; 

        // read in a loop and fill up buffer
        // once we have filled the currently buffer, continue parsing
        bool ready_to_continue_parsing = false;
        while (!ready_to_continue_parsing && !parser->is_done()) {

            beast::http::read_some(session_ptr->stream(), session_ptr->get_buffer(), *parser, ec);

            // need buffer means we have filled the current parser, write it to iRODS
            if (ec == beast::http::error::need_buffer) {
                ready_to_continue_parsing = true;
                ec = {};
            }

            if (ec) {
                log::error("{}: Error when parsing file - {}", func, ec.what());
                response.result(beast::http::status::internal_server_error);
                log::debug("{}: returned {}", func, response.reason());
                session_ptr->send(std::move(response));
                return;
            }
        }

        bool need_more = false;

        // add the current buffer into the parsing_buffer_string
        size_t bytes_read = read_buffer_size - parser_message.body().size;
        parsing_buffer_string.append(buf_vector.data(), bytes_read);

        // continue parsing until we need more bytes in parsing_buffer_string
        while (!parser->is_done() || !parsing_buffer_string.empty()) {

            // break out if at a terminal state
            if (current_state == parsing_state::parsing_done || current_state == parsing_state::parsing_error) {
                break;
            }

            // if we have read all from the parser but need more bytes enter error state
            if (parser->is_done() && need_more) {
                log::error("{}: Ran out of bytes before finished parsing", func);
                current_state = parsing_state::parsing_error;
                break;
            }

            // if we need more, break out and continue in a new background thread
            if (need_more) {
                break;
            }

            switch (current_state) {
                case parsing_state::header_begin:
                {
                    // Chunk headers can be of the following forms:
                    // 1. With extensions: <hex>;extension1=extension1value;extension2=extension2value\r\n
                    // 2. Without extensions: <hex>\r\n
                    
                    // See if it is of form 1.
                    size_t semicolon_location = parsing_buffer_string.find (";");
                    if (semicolon_location == std::string::npos) {

                        // Not form 1.  See if it is form 2.
                        size_t newline_location = parsing_buffer_string.find("\r\n");
                        if (newline_location != std::string::npos) {
                            std::string chunk_size_str = parsing_buffer_string.substr(0, newline_location);
                            size_t hex_digits_parsed = 0;
                            try {
                                chunk_size = stoull(chunk_size_str, &hex_digits_parsed, 16);
                            } catch (std::invalid_argument& e) {
                                hex_digits_parsed = 0;
                            }

                            if (hex_digits_parsed == chunk_size_str.length()) {
                                // eat the bytes up to and including \r\n 
                                parsing_buffer_string = parsing_buffer_string.substr(newline_location+2);
                                if (chunk_size == 0) {
                                    current_state = parsing_state::end_of_chunk;
                                } else {
                                    current_state = parsing_state::body;
                                }
                            } else {
                                log::error("{}: bad chunk size: {}", func, chunk_size_str);
                                current_state = parsing_state::parsing_error;
                            }
                        } else if (!parser->is_done()) {
                            need_more = true;
                        } else {
                            // we have received all of the bytes but do not have "<hex>\r\n" sequence
                            log::error("{}: Malformed chunk header", func);
                            current_state = parsing_state::parsing_error;
                        }
                    } else {
                        // semicolon found
                        std::string chunk_size_str = parsing_buffer_string.substr(0, semicolon_location);
                        size_t hex_digits_parsed = 0;
                        try {
                           chunk_size = stoull(chunk_size_str, &hex_digits_parsed, 16);
                        } catch (std::invalid_argument& e) {
                            hex_digits_parsed = 0;
                        }
                        if (hex_digits_parsed == chunk_size_str.length()) {
                            // eat the bytes up to and including semicolon
                            parsing_buffer_string = parsing_buffer_string.substr(semicolon_location+1);
                            current_state = parsing_state::header_continue;
                        } else {
                            log::error("{}: bad chunk size: {}", func, chunk_size_str);
                            current_state = parsing_state::parsing_error;
                        }
                    }
                    break;
                }
                case parsing_state::header_continue:
                {
                    // move beyond the newline 
                    size_t newline_location = parsing_buffer_string.find("\r\n");

                    // set string to after the \r\n
                    if (newline_location != std::string::npos) {
                        parsing_buffer_string = parsing_buffer_string.substr(newline_location+2);
                        if (chunk_size == 0) {
                            current_state = parsing_state::end_of_chunk;
                        } else {
                            current_state = parsing_state::body;
                        }
                    } else if (!parser->is_done()) {
                        need_more = true;
                    } else {
                        // we have read all the bytes but do not have a \r\n at the end
                        // of the header line
                        log::error("{}: Malformed chunk header", func);
                        current_state = parsing_state::parsing_error;
                    }
                    break;
                }
                case parsing_state::body:
                {
                    // if we have the full chunk, handle it otherwise continue
                    // until we do
                    if (parsing_buffer_string.length() >= chunk_size) {
                        std::string body = parsing_buffer_string.substr(0, chunk_size);

                        try {
                            if (upload_part) {
                                ofs->write(body.c_str(), body.length());
                            } else {
                                d->write(body.c_str(), body.length());
                            }
                        }
                        catch (std::exception& e) {
                            log::error("{}: Exception when writing to file - {}", func, e.what());
                            response.result(beast::http::status::internal_server_error);
                            log::debug("{}: returned {}", func, response.reason());
                            session_ptr->send(std::move(response));
                            return;
                        }

                        // reset string stream and set it to after the \r\n
                        parsing_buffer_string = parsing_buffer_string.substr(chunk_size);
                        current_state = parsing_state::end_of_chunk;
                    } else {
                        // Note to save memory we could stream the bytes we have, decrease
                        // chunk size, and discard these bytes.
                        need_more = true;
                    }
                    break;
                }
                case parsing_state::end_of_chunk:
                {
                    // If the size of parsing_buffer_string is just one and consists of "\r"
                    // then we need to get more bytes.
                    if (!parser->is_done() && parsing_buffer_string.size() == 1 && parsing_buffer_string[0] == '\r') {
                        // we don't have enough bytes to read the expected "\r\n"
                        // but there are more bytes to be read
                        need_more = true;
                        break;
                    }

                    // If the size is 0 then we need to get more bytes.
                    if (!parser->is_done() && parsing_buffer_string.size() == 0) {
                        // we don't have enough bytes to read the expected "\r\n"
                        // but there are more bytes to be read
                        need_more = true;
                        break;
                    }

                    size_t newline_location = parsing_buffer_string.find("\r\n");
                    if (newline_location != 0) {
                        log::error("{}: Invalid chunk end sequence", func);
                        current_state = parsing_state::parsing_error;
                    } else {
                        // remove \r\n and go to next chunk
                        parsing_buffer_string = parsing_buffer_string.substr(2);
                        if (chunk_size == 0) {
                            current_state = parsing_state::parsing_done;
                        } else {
                            current_state = parsing_state::header_begin;
                        }
                    }
                    break;
                }
                default:
                    break;
            }

            // if we are done return ok
            if (current_state == parsing_state::parsing_done) {
                response.result(beast::http::status::ok);
                log::debug("{}: returned {}:{}", func, response.reason(), __LINE__);
                session_ptr->send(std::move(response)); 
                return;
            } else if (current_state == parsing_state::parsing_error) {
                log::error("{}: Error parsing chunked body", func);
                response.result(boost::beast::http::status::bad_request);
                log::debug("{}: returned {}", func, response.reason());
                session_ptr->send(std::move(response));
                return;
            }
        }

        // schedule a new task to continue
        manually_parse_chunked_body_write_to_irods_in_background(
                session_ptr,
                response,
                parser,
                read_buffer_size,
                ofs,
                d,
                upload_part,
                current_state,
                chunk_size,
                parsing_buffer_string,
                func);
    });
}

void beast_parse_body_write_to_irods_in_background(
    irods::http::session_pointer_type session_ptr,
    beast::http::response<beast::http::empty_body>& response_,
    std::shared_ptr<beast::http::request_parser<boost::beast::http::buffer_body>> parser,
    uint64_t read_buffer_size,
    std::shared_ptr<std::ofstream> ofs,
    std::shared_ptr<irods::experimental::io::odstream> d,
    bool upload_part,
    uint64_t total_bytes_read,
    const::std::string part_number,
    const std::string func)
{
    irods::http::globals::background_task([session_ptr,
        response = std::move(response_),
        parser,
        read_buffer_size,
        ofs,
        d,
        upload_part,
        total_bytes_read,
        part_number,
        func]() mutable {

        auto& parser_message = parser->get();
        boost::beast::error_code ec;

        std::vector<char> buf_vector(read_buffer_size);
        parser_message.body().data = buf_vector.data();
        parser_message.body().size = read_buffer_size; 

        beast::http::read(session_ptr->stream(), session_ptr->get_buffer(), *parser, ec);

        size_t size_left_in_buffer = parser_message.body().size;

        // need buffer means we have filled the current parser, write it to iRODS
        if (ec == beast::http::error::need_buffer) {
            ec = {};
        }

        if (ec) {
            log::error("{}: Error when parsing file - {} - part_number={}, total_bytes_read={} size_left_in_buffer={}", func, ec.what(), part_number, total_bytes_read, size_left_in_buffer);
            response.result(beast::http::status::internal_server_error);
            log::debug("{}: returned {}", func, response.reason());
            session_ptr->send(std::move(response));
            return;
        }

        size_t bytes_read = read_buffer_size - parser_message.body().size;
        total_bytes_read += bytes_read;
        try {
            log::trace("{}: part_number={}, bytes_read/written={} total_bytes_read/written={} buf_vector.data()={}", func, part_number, bytes_read, total_bytes_read, static_cast<void*>(buf_vector.data()));
            if (upload_part) {
                ofs->write((char*) buf_vector.data(), bytes_read);
                log::trace("{}: part_number={}, wrote {} bytes", func, part_number, bytes_read);
            } else {
                d->write((char*) buf_vector.data(), bytes_read);
                log::trace("{}: part_number={}, wrote {} bytes", func, part_number, bytes_read);
            }
        }
        catch (std::exception& e) {
            log::error("{}: Exception when writing to file - {}", func, e.what());
            response.result(beast::http::status::internal_server_error);
            log::debug("{}: returned {}", func, response.reason());
            session_ptr->send(std::move(response));
            return;
        }

        if (parser->is_done()) {
            response.result(beast::http::status::ok);
            log::debug("{}: returned {}", func, response.reason());
            session_ptr->send(std::move(response)); 
            return;
        }

        // schedule a new task to continue
        beast_parse_body_write_to_irods_in_background(
                session_ptr,
                response,
                parser,
                read_buffer_size,
                ofs,
                d,
                upload_part,
                total_bytes_read,
                part_number,
                func);
    });
}
