#ifndef IRODS_S3_API_S3_API_HPP
#define IRODS_S3_API_S3_API_HPP
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/beast.hpp>
#include <irods/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/url.hpp>

#include "irods/private/s3_api/common.hpp"

namespace irods::s3::actions
{
	void handle_listobjects_v2(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_listbuckets(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_getobject(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_deleteobject(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_deleteobjects(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_putobject(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_headobject(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_headbucket(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_copyobject(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_createmultipartupload(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_completemultipartupload(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

	void handle_abortmultipartupload(
		irods::http::session_pointer_type sess_ptr,
		boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view&);

} //namespace irods::s3::actions
#endif
