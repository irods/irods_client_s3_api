#include "./authentication.hpp"
#include "./hmac.hpp"

#include "boost/url/url.hpp"
#include "boost/url/url_view.hpp"
#include "./connection.hpp"
#include "plugin.hpp"
#include "s3/s3_api.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http/buffer_body.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/stacktrace.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/system/system_error.hpp>
#include <boost/url/src.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <irods/filesystem/filesystem.hpp>
#include <irods/irods_client_api_table.hpp>
#include <irods/irods_pack_table.hpp>
#include <irods/rodsGenQuery.h>
#include <memory>
#include <string_view>
#include <curl/curl.h>

namespace asio = boost::asio;
namespace this_coro = boost::asio::this_coro;
namespace beast = boost::beast;

asio::awaitable<void> handle_request(asio::ip::tcp::socket socket)
{
    beast::http::parser<true, beast::http::buffer_body> parser;

    std::string buf_back;
    auto buffer = beast::flat_buffer();
    boost::system::error_code ec;
    std::cout << "Received " << beast::http::read_header(socket, buffer, parser, ec) << " bytes\n";
    if (ec) {
        // handle me please!
    }
    for (const auto& field : parser.get()) {
        std::cout << "header: " << field.name_string() << ":" << field.value() << std::endl;
    }
    std::cout << "target: " << parser.get().target() << std::endl;
    std::string url_string = static_cast<std::string>(parser.get().find("Host")->value()).append(parser.get().target());
    std::cout << "candidate url string is [" << url_string << "]\n";
    boost::urls::url url2;
    auto host = parser.get().find("Host")->value();
    url2.set_encoded_host(host.find(':') != std::string::npos ? host.substr(0, host.find(':')) : host);
    url2.set_path(parser.get().target().substr(0, parser.get().target().find("?")));
    url2.set_scheme("http");
    if (parser.get().target().find('?') != std::string::npos) {
        url2.set_encoded_query(parser.get().target().substr(parser.get().target().find("?") + 1));
    }

    boost::urls::url_view url = url2;
    std::cout << "Url " << url2 << std::endl;
    const auto& segments = url.segments();
    const auto& params = url.params();
    std::cout << segments << " " << segments.empty() << std::endl;
    switch (parser.get().method()) {
        case boost::beast::http::verb::get:
            if (segments.empty() || params.contains("encoding-type") || params.contains("list-type")) {
                // Among other things, listobjects should be handled here.

                // This is a weird little thing because the parameters are a multimap.
                auto f = url.params().find("list-type");

                // Honestly not being able to use -> here strikes me as a potential mistake that
                // will be corrected in the future when boost::url is released properly as part
                // of boost
                if (f != url.params().end() && (*f).value == "2") {
                    std::cout << "Listobjects detected" << std::endl;
                    co_await irods::s3::actions::handle_listobjects_v2(socket, parser, url);
                }
            }
            else {
                // GetObject

                if (url.params().find("location") != url.params().end() && url.segments().size() > 1) {
                    // This is GetBucketLocation
                    std::cout << "GetBucketLocation detected" << std::endl;
                    beast::http::response<beast::http::string_body> resp;
                    resp.body() = "<?xml version='1.0' encoding='utf-8'?>"
                                  "<LocationConstraint>"
                                  "   <LocationConstraint>a-computer-1</LocationConstraint>"
                                  "</LocationConstraint>";
                    co_await beast::http::async_write(socket, resp, asio::use_awaitable);
                    co_return;
                }
                else {
                    std::cout << "getobject detected" << std::endl;
                    co_await irods::s3::actions::handle_getobject(socket, parser, url);
                }
            }
            break;
        case boost::beast::http::verb::put:
            if (parser.get().find("x-amz-copy-source") != parser.get().end()) {
                // copyobject
                std::cout << "Copyobject detected" << std::endl;
                co_await irods::s3::actions::handle_copyobject(socket, parser, url);
            }
            else {
                // putobject
                std::cout << "putobject detected" << std::endl;
                co_await irods::s3::actions::handle_putobject(socket, parser, url);
                co_return;
            }
            break;
        case boost::beast::http::verb::delete_:
            if (segments.empty()) {
                std::cout << "Deletebucket detected?" << std::endl;
            }
            else {
                std::cout << "Deleteobject detected" << std::endl;
                co_await irods::s3::actions::handle_deleteobject(socket, parser, url);
                co_return;
            }
            break;
        case boost::beast::http::verb::head:
            // Probably just headbucket and headobject here.
            // and headbucket isn't on the immediate list
            // of endpoints.
            if (url.segments().empty()) {
                std::cout << "Headbucket detected" << std::endl;
            }
            else {
                std::cout << "Headobject detected" << std::endl;
                co_await irods::s3::actions::handle_headobject(socket, parser, url);
                co_return;
            }
            break;
            /*
        case boost::beast::http::verb::delete_:
            // DeleteObject
            std::cout << "Deleteobject detected" << std::endl;
            break;
            */
        default:
            std::cerr << "Someone tried to make an HTTP request with a method that is not yet supported\n";
    }
    char buf[512];
    while (!parser.is_done()) {
        std::cout << "Reading" << std::endl;
        parser.get().body().data = buf;
        parser.get().body().size = sizeof(buf);
        std::cout << std::string_view((char*) parser.get().body().data, parser.get().body().size) << std::endl;
        // Using async_read here causes it to completely eat the entire input without handling it properly.
        auto read = co_await beast::http::async_read_some(socket, buffer, parser, asio::use_awaitable);
        std::cout << "Read " << read << " bytes" << std::endl;
        if (ec == beast::http::error::need_buffer) {
            ec = {};
        }
        else if (ec) {
            co_return;
        }
    }
    co_return;
}

asio::awaitable<void> listener(unsigned short port)
{
    auto executor = co_await this_coro::executor;
    asio::ip::tcp::acceptor acceptor(executor, {asio::ip::tcp::v4(), port});
    for (;;) {
        asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);
        asio::co_spawn(executor, handle_request(std::move(socket)), asio::detached);
        std::cout << std::flush;
    }
}

/// \brief Load the configuration
/// \param port out The location to write the acquired port number
/// \returns The configuration object.
nlohmann::json load_configuration(const std::string_view _config_path, unsigned short& port);

int main(int _argc, char* _argv[])
{
    if (_argc < 2) {
        std::cerr << "Error: Missing configuration file path.\n\n"
                     "USAGE: irods_s3_bridge CONFIG_FILE\n";
    }

    unsigned short port = 8080;

    irods::api_entry_table& api_tbl = irods::get_client_api_table();
    irods::pack_entry_table& pk_tbl = irods::get_pack_table();
    init_api_table(api_tbl, pk_tbl);

    const auto config_value = load_configuration(_argv[1], port);

    const auto s3_server = config_value.at("s3_server");
    const auto iter = s3_server.find("threads");
    const auto thread_count = (iter != std::end(s3_server)) ? iter->get<int>() : std::thread::hardware_concurrency();
    asio::io_context io_context(thread_count);

    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) { io_context.stop(); });

    asio::co_spawn(io_context, listener(port), boost::asio::detached);
    io_context.run();

    return 0;
}

nlohmann::json load_configuration(const std::string_view _config_path, unsigned short& port)
{
    nlohmann::json config_value;

    if (!std::filesystem::exists(_config_path)) {
        std::cout
            << "You need to create config.json and populate it with an authentication plugin and a bucket plugin"
            << std::endl;
        return 1;
    }
    std::ifstream configuration_file(_config_path);

    configuration_file >> config_value;
    irods::s3::set_config(config_value);

    const auto& s3_server = config_value.at("s3_server");

    auto i = irods::s3::get_connection();
    for (const auto& [k, v] : s3_server.at("plugins").items()) {
        std::cout << "Loading plugin " << k << std::endl;
        irods::s3::plugins::load_plugin(*i, k, v);
    }
    if (s3_server.find("resource") != s3_server.end()) {
        irods::s3::set_resource(s3_server.value<std::string>("resource", ""));
    }
    port = s3_server.value("port", 8080);

    if (!irods::s3::plugins::authentication_plugin_loaded()) {
        std::cout
            << "No authentication plugin is specified or loaded" << std::endl
            << "Consider setting up the static_authentication_plugin, add a section like" << std::endl
            << R"("static_authentication_resolver": {)"
               R"(""name": "static_authentication_resolver",)"
               R"(""users": {"<The s3 username>": {"username": "<The iRODS username>","secret_key": "<your favorite secret key>"}})"
               "}"
            << std::endl
            << "to the 'plugins' object in your config.json" << std::endl;
    }
    if (!irods::s3::plugins::bucket_plugin_loaded()) {
        std::cout << "No bucket resolution plugin is specified or loaded" << std::endl
                  << "Consider setting up the static_authentication_plugin, add a section like" << std::endl
                  << R"("static_bucket_resolver": {)"
                     R"("name": "static_bucket_resolver",)"
                     R"("mappings": {)"
                     R"(<Your Bucket's name>": "<The root of your bucket in irods>")"
                     "}"
                  << std::endl
                  << "to the 'plugins' object in your config.json" << std::endl;
    }

    return config_value;
}
