#ifndef IRODS_S3_API_COMMON_ROUTINES_HPP
#define IRODS_S3_API_COMMON_ROUTINES_HPP

#include <string>

#include <fmt/format.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <fmt/chrono.h>
#pragma clang diagnostic pop

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/common.hpp"

namespace irods::s3::api::common_routines
{

	inline std::string convert_time_t_to_str(const time_t& t, const std::string_view format)
	{
		return fmt::format(fmt::runtime(format), fmt::localtime(t));
	}

	inline void send_error_response(
		irods::http::session_pointer_type session_ptr,
		const boost::beast::http::status status_code,
		const std::string& s3_error_code,
		const std::string& message,
		const std::string& s3_path,
		const std::string& func)
	{
		boost::beast::http::response<boost::beast::http::string_body> response;

		std::string request_id = boost::lexical_cast<std::string>(boost::uuids::random_generator()());
		irods::http::logging::error("{}: {} - {}", func, request_id, message);
		response.result(status_code);
		response.set(boost::beast::http::field::content_type, "text/xml");

		// build xml response
		boost::property_tree::ptree document;
		document.add("Error", "");
		document.add("Error.Code", s3_error_code.c_str());
		document.add("Error.Message", message.c_str());
		document.add("Error.Resource", s3_path.c_str());
		document.add("Error.RequestId", request_id.c_str());

		// add the xml to the response object
		std::stringstream s;
		boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
		settings.indent_char = ' ';
		settings.indent_count = 4;
		boost::property_tree::write_xml(s, document, settings);
		response.body() = s.str();

		response.prepare_payload();

		// log and send the response
		irods::http::logging::debug("{}: {} - returned {}", func, request_id, response.reason());
		irods::http::logging::debug("{}: {} - response xml\n{}", func, request_id, response.body());
		session_ptr->send(std::move(response));
		return;
	}
} //namespace irods::s3::api::common_routines

#endif // IRODS_S3_API_COMMON_ROUTINES_HPP
