#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"

#include <irods/irods_exception.hpp>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

void irods::s3::actions::handle_copyobject(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
	const boost::urls::url_view& url)
{
	beast::http::response<beast::http::empty_body> response;

	auto irods_username = irods::s3::authentication::authenticates(parser, url);
	if (!irods_username) {
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	auto conn = irods::get_connection(*irods_username);

	auto url2 = boost::urls::url(parser.get()["x-amz-copy-source"]);
	fs::path destination_path, source_path;
	if (auto bucket = irods::s3::resolve_bucket(url2.segments()); bucket.has_value()) {
		source_path = irods::s3::finish_path(bucket.value(), url2.segments());
	}
	else {
		logging::debug("{}: Could not locate source path", __FUNCTION__);
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		destination_path = irods::s3::finish_path(bucket.value(), url.segments());
	}
	else {
		logging::debug("{}: Could not locate destination path", __FUNCTION__);
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	if (source_path.empty() || destination_path.empty()) {
		response.result(beast::http::status::not_found);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	try {
		fs::client::copy(conn, source_path, destination_path, fs::copy_options::overwrite_existing);
	}
	catch (irods::experimental::filesystem::filesystem_error& ex) {
		switch (ex.code().value()) {
				// It's funny that it uses iRODS codes here in what seems likely to have been meant for
				// things like ENOFILE or EPERM
			case USER_ACCESS_DENIED:
			case CAT_NO_ACCESS_PERMISSION:
				response.result(beast::http::status::forbidden);
				break;
			default:
				logging::error("{}: Returned exception {}", __FUNCTION__, ex.what());
				response.result(beast::http::status::internal_server_error);
				break;
		}
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	catch (std::system_error& e) {
		logging::error("{}: {}", __FUNCTION__, e.what());
		response.result(beast::http::status::internal_server_error);
		logging::debug("{}: returned [{}]", __FUNCTION__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	logging::trace("{}: Copied object{}", __FUNCTION__, response.reason());
	// We don't have real etags, so using the md5 here would be confusing, as it would match any number of distinct
	// objects The most accurate representation of an Etag that I am aware of that we can get "for free" is using the
	// md5 sum appended to the path of the object. This makes it both content-sensitive and location sensitive.
	beast::http::response<beast::http::string_body> string_body_response(std::move(response));
	string_body_response.body() = "<CopyObjectResult><ETag>TBD</ETag></CopyObjectResult>";
	logging::debug("{}: returned [{}]", __FUNCTION__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
	return;
}
