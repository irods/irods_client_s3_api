#ifndef IRODS_S3_API_S3_API_HPP
#define IRODS_S3_API_S3_API_HPP
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/beast.hpp>
#include <irods/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/url.hpp>

#include "../types.hpp"
#include "../connection.hpp"

namespace irods::s3::actions
{
    boost::asio::awaitable<void> handle_listobjects_v2(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_listbuckets(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_getobject(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_deleteobject(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_putobject(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_headobject(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);

    boost::asio::awaitable<void> handle_copyobject(
        boost::asio::ip::tcp::socket& socket,
        static_buffer_request_parser& parser,
        const boost::urls::url_view& url);
} //namespace irods::s3::actions
#endif
