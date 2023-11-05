#include "../types.hpp"
#include "s3_api.hpp"
#include "../bucket.hpp"
#include "../connection.hpp"
#include "../authentication.hpp"
#include "../common_routines.hpp"
#include "../configuration.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <experimental/coroutine>
#include <boost/beast.hpp>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/url.hpp>
#include <boost/lexical_cast.hpp>

#include <irods/filesystem.hpp>
#include <irods/query_builder.hpp>

#include <iostream>
#include <unordered_set>
#include <chrono>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;

static const std::string date_format{"{:%Y-%m-%dT%H:%M:%S+00:00}"};

asio::awaitable<void> irods::s3::actions::handle_listbuckets(
    asio::ip::tcp::socket& socket,
    static_buffer_request_parser& parser,
    const boost::urls::url_view& url)
{
    using namespace boost::property_tree;

    auto rcComm_t_ptr = irods::s3::get_connection();
    auto irods_username = irods::s3::authentication::authenticates(*rcComm_t_ptr, parser, url);

    if (!irods_username) {
        beast::http::response<beast::http::empty_body> response;
        response.result(beast::http::status::forbidden);
        beast::http::write(socket, response);
        co_return;
    }

    // Reconnect to the iRODS server as the target user.
    // The rodsadmin account from the config file will act as the proxy for the user.
    rcComm_t_ptr = irods::s3::get_connection(irods_username);

    boost::property_tree::ptree document;
    document.add("ListAllMyBucketsResult", "");
    document.add("ListAllMyBucketsResult.Buckets", "");

    // get the buckets from the configuration
    const auto bucket_list  = get_config().at(nlohmann::json::json_pointer{"/s3_server/plugins/static_bucket_resolver/mappings"});
    for (const auto& [bucket, collection] : bucket_list.items()) {

        // Get the creation time for the collection
        bool found = false;
        std::string query;
        std::time_t create_collection_epoch_time = 0;

        query = fmt::format(
                "select COLL_CREATE_TIME where COLL_NAME = '{}'",
                collection.get_ref<const std::string&>());

        std::cout << "query: " << query << std::endl;

        for (auto&& row : irods::query<RcComm>(rcComm_t_ptr.get(), query)) {
            found = true;
            create_collection_epoch_time = boost::lexical_cast<std::time_t>(row[0]);
            break;
        }

        // If creation time not found, user does not have access to the collection the bucket
        // maps to.  Do not add this bucket to the list.
        if (found) {
             std::string create_collection_epoch_time_str = irods::s3::api::common_routines::convert_time_t_to_str(create_collection_epoch_time, date_format);

             ptree object;
             object.put("CreationDate", create_collection_epoch_time_str);
             object.put("Name", bucket);
             document.add_child("ListAllMyBucketsResult.Buckets.Bucket", object);
        }
    }
    document.add("ListAllMyBucketsResult.Owner", "");

    std::stringstream s;
    boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
    settings.indent_char = ' ';
    settings.indent_count = 4;
    boost::property_tree::write_xml(s, document, settings);
    beast::http::response<beast::http::string_body> response;
    response.body() = s.str();
    std::cout << s.str();

    beast::http::write(socket, response);
    co_return;
}
