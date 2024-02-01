#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/configuration.hpp"

#include <irods/irods_exception.hpp>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace log = irods::http::log;

void irods::s3::actions::handle_createmultipartupload(
    irods::http::session_pointer_type session_ptr,
    boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
    const boost::urls::url_view& url)
{
    beast::http::response<beast::http::empty_body> response;

    // Authenticate
    auto irods_username = irods::s3::authentication::authenticates(parser, url);
    if (!irods_username) {
        log::error("{}: Failed to authenticate.", __FUNCTION__);
        response.result(beast::http::status::forbidden);
        log::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }

    auto conn = irods::get_connection(*irods_username);
    
    std::filesystem::path s3_bucket;
    std::filesystem::path s3_key;

    bool on_bucket = true;
    for (auto seg : url.encoded_segments()) {
        if (on_bucket) {
            on_bucket = false;
            s3_bucket = seg.decode();
        } else {
            s3_key = s3_key / seg.decode();
        }
    }
   
    log::debug("{} s3_bucket={} s3_key={}", __FUNCTION__, s3_bucket.string(), s3_key.string());

    fs::path path;
    if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
        path = bucket.value();
        path = irods::s3::finish_path(path, url.segments());
        log::debug("{}: CreateMultipartUpload path={}", __FUNCTION__, path.string());
    } else {
        log::error("{}: Failed to resolve bucket", __FUNCTION__);
        response.result(beast::http::status::forbidden);
        log::debug("{}: returned {}", __FUNCTION__, response.reason());
        session_ptr->send(std::move(response)); 
        return;
    }

    beast::http::response<beast::http::string_body> string_body_response(std::move(response));
    string_body_response.result(boost::beast::http::status::ok);

    // create the UploadId
    std::string upload_id = boost::lexical_cast<std::string>(boost::uuids::random_generator()());

    boost::property_tree::ptree document;
    document.add("InitiateMultipartUploadResult", "");
    document.add("InitiateMultipartUploadResult.Bucket", s3_bucket.c_str());
    document.add("InitiateMultipartUploadResult.Key", s3_key.c_str());
    document.add("InitiateMultipartUploadResult.UploadId", upload_id.c_str());

    std::stringstream s;
    boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
    settings.indent_char = ' ';
    settings.indent_count = 4;
    boost::property_tree::write_xml(s, document, settings);
    string_body_response.body() = s.str();
    std::cout << "------ CreateMultipartUpload Response Body -----" << std::endl;
    std::cout << s.str() << std::endl;

    session_ptr->send(std::move(string_body_response)); 

    return;
}
