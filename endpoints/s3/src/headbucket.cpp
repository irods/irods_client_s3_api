#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

#include <irods/irods_exception.hpp>

#include <fmt/format.h>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

void irods::s3::actions::handle_headbucket(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
	const boost::urls::url_view& url)
{
	beast::http::response<beast::http::empty_body> response;
	response.result(beast::http::status::forbidden);
	try {
		auto irods_username = irods::s3::authentication::authenticates(parser, url);

		if (!irods_username) {
			response.result(beast::http::status::forbidden);
			logging::debug("{}: returned {}", __FUNCTION__, response.reason());
			session_ptr->send(std::move(response));
			return;
		}
		auto conn = irods::get_connection(*irods_username);

		fs::path path;
		if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
			path = irods::s3::finish_path(bucket.value(), url.segments());
		}
		else {
			std::cout << "Failed to resolve bucket" << std::endl;
			response.result(beast::http::status::forbidden);
			logging::debug("{}: returned {}", __FUNCTION__, response.reason());
			session_ptr->send(std::move(response));
			return;
		}

		if (fs::client::exists(conn, path)) {
			response.result(boost::beast::http::status::ok);
			std::cout << response.result() << std::endl;
			logging::debug("{}: returned {}", __FUNCTION__, response.reason());
			session_ptr->send(std::move(response));
			return;
		}

		// This could be that it doesn't exist or that the user doesn't have permission.
		// Returning forbidden.
		response.result(boost::beast::http::status::forbidden);
		logging::debug("{}: returned {}", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	catch (const std::system_error& e) {
		std::cout << e.what() << std::endl;
		switch (e.code().value()) {
			case USER_ACCESS_DENIED:
			case CAT_NO_ACCESS_PERMISSION:
				response.result(beast::http::status::forbidden);
				logging::debug("{}: returned {}", __FUNCTION__, response.reason());
				break;
			default:
				response.result(beast::http::status::internal_server_error);
				logging::debug("{}: returned {}", __FUNCTION__, response.reason());
				break;
		}
	}

	logging::debug("{}: returned {}", __FUNCTION__, response.reason());
	session_ptr->send(std::move(response));
}
