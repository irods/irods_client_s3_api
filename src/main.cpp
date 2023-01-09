#include "./authentication.hpp"
#include "./event_loop.hpp"
#include "./hmac.hpp"
#include "./bucket.hpp"
#include "boost/url/param.hpp"
#include "boost/url/url.hpp"
#include "boost/url/url_view.hpp"
#include "./connection.hpp"
#include "./types.hpp"
#include "plugin.hpp"
#include "s3/s3_api.hpp"

#include <algorithm>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/detail/descriptor_ops.hpp>
#include <boost/asio/detail/socket_ops.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http/buffer_body.hpp>
#include <boost/beast/http/detail/type_traits.hpp>
#include <boost/beast/http/dynamic_body.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/property_tree/detail/xml_parser_writer_settings.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <boost/stacktrace.hpp>

#include <boost/beast/http/serializer.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/type_traits.hpp>

#include <boost/beast/http/verb.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/stacktrace/stacktrace_fwd.hpp>
#include <boost/system/system_error.hpp>
#include <boost/url/src.hpp>

#include <chrono>
#include <ctype.h>
#include <experimental/coroutine>
#include <filesystem>
#include <iomanip>
#include <ios>
#include <iostream>
#include <fstream>

#include <fmt/chrono.h>
#include <fmt/format.h>

#include <irods/filesystem/collection_entry.hpp>
#include <irods/filesystem/collection_iterator.hpp>
#include <irods/filesystem/filesystem.hpp>
#include <irods/filesystem/filesystem_error.hpp>
#include <irods/filesystem/path.hpp>
#include <irods/genQuery.h>
#include <irods/msParam.h>
#include <irods/rcConnect.h>
#include <irods/rodsClient.h>
#include <irods/client_connection.hpp>
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

#include <memory>
#include <string_view>
#include <type_traits>
#include <unordered_set>

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
    std::string url_string = parser.get().find("Host")->value().to_string() + parser.get().target().to_string();
    std::cout << "candidate url string is [" << url_string << "]\n";
    boost::urls::url url2;
    auto host = parser.get().find("Host")->value();
    url2.set_encoded_host(host.find(':') != std::string::npos ? host.substr(0, host.find(':')) : host);
    url2.set_path(parser.get().target().substr(0, parser.get().target().find("?")));
    url2.set_scheme("http");
    if (parser.get().target().find('?') != std::string::npos) {
        url2.set_query(parser.get().target().substr(parser.get().target().find("?") + 1));
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
                    co_await irods::s3::actions::handle_listobjects_v2(socket, parser, url);
                }
            }
            else {
                // GetObject
                std::cout << "getobject detected" << std::endl;
                co_await irods::s3::actions::handle_getobject(socket, parser, url);
            }
            break;
        case boost::beast::http::verb::put:
            if (parser.get().find("x-amz-copy-source") != parser.get().end()) {
                // copyobject
                std::cout << "Copyobject detected" << std::endl;
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
                std::cout << "Deletebucket detected?" << std::endl
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
            // of starting point.
            if (url.segments().empty()) {
                std::cout << "Headbucket detected" << std::endl;
            }
            else {
                std::cout << "Headobject detected" << std::endl;
            }
            break;
        case boost::beast::http::verb::delete_:
            // DeleteObject
            std::cout << "Deleteobject detected" << std::endl;
            break;
        default:
            std::cerr << "Oh no..." << std::endl;
            exit(37);
            break;
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

asio::awaitable<void> listener()
{
    auto executor = co_await this_coro::executor;
    asio::ip::tcp::acceptor acceptor(executor, {asio::ip::tcp::v4(), 8080});
    for (;;) {
        asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);
        asio::co_spawn(executor, handle_request(std::move(socket)), asio::detached);
        std::cout << "Accepted?" << std::endl;
    }
}

int main()
{
    using namespace nlohmann::literals;
    irods::api_entry_table& api_tbl = irods::get_client_api_table();
    irods::pack_entry_table& pk_tbl = irods::get_pack_table();
    init_api_table(api_tbl, pk_tbl);
    {
        auto config = R"({"name":"static_bucket_resolver", "mappings": {"wow": "/tempZone/home/rods/wow/"}})"_json;
        auto i = irods::s3::get_connection();
        irods::s3::plugins::load_plugin(*i, "static_bucket_resolver", config);
    }
    {
        auto config =
            R"({"name":"static_authentication_resolver", "users": {"no": {"username":"rods","secret_key":"heck"}}})"_json;
        auto i = irods::s3::get_connection();
        irods::s3::plugins::load_plugin(*i, "static_authentication_resolver", config);
    }

    asio::io_context io_context(1);
    auto address = asio::ip::make_address("0.0.0.0");
    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) { io_context.stop(); });
    asio::co_spawn(io_context, listener(), boost::asio::detached);
    io_context.run();
    return 0;
}
