#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/hmac.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/log.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include <irods/rcMisc.h>
#include <irods/rodsKeyWdDef.h>

#include <date/date.h>

namespace
{

	std::string uri_encode(const std::string_view sv)
	{
		std::stringstream s;
		std::ios state(nullptr);
		state.copyfmt(s);
		for (auto c : sv) {
			bool encode = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			              boost::is_any_of("-_~.")(c);
			if (!encode) {
				// Interestingly, most hex-encoded values in the amazon api tend to be lower case,
				// except for this.
				s << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int) c;
				s.copyfmt(state);
			}
			else {
				s << c;
			}
		}
		return s.str();
	}

	std::string
	get_user_signing_key(const std::string_view secret_key, const std::string_view date, const std::string_view region)
	{
		namespace logging = irods::http::logging;
		logging::debug("date time component is {}", date);
		auto date_key = irods::s3::authentication::hmac_sha_256(std::string("AWS4").append(secret_key), date);
		auto date_region_key = irods::s3::authentication::hmac_sha_256(date_key, region);
		auto date_region_service_key = irods::s3::authentication::hmac_sha_256(date_region_key, "s3");
		return irods::s3::authentication::hmac_sha_256(date_region_service_key, "aws4_request");
	}

	// TODO we can improve performance by reusing the same stringstream where possible.

	// Turn the url into the 'canon form'
	std::string canonicalize_url(const boost::urls::url_view& url)
	{
		namespace logging = irods::http::logging;
		std::stringstream result;
		logging::debug("{}:{} ({}) url={}", __FILE__, __LINE__, __FUNCTION__, url.path());
		for (const auto i : url.segments()) {
			result << '/' << uri_encode(i);
		}
		return result.str();
	}

	std::string to_lower(const std::string_view sv)
	{
		std::string r;
		for (auto i : sv) {
			r.push_back(tolower(i));
		}
		return r;
	}
	std::string canonicalize_request(
		const boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
		const boost::urls::url_view& url,
		const std::vector<std::string>& signed_headers)
	{
		namespace logging = irods::http::logging;

		// At various points the signature process wants various fields to be sorted.
		// so reusing this can at least avoid some of the duplicate allocations and such
		std::vector<std::string_view> sorted_fields;

		std::stringstream result;

		std::ios state(nullptr);
		state.copyfmt(result);

		// HTTP Verb
		result << parser.get().method_string() << '\n';
		result.copyfmt(result); // re store former formatting

		// Canonical URI
		result << canonicalize_url(url) << '\n';

		// Canonical Query String
		{
			bool first = true;
			// Changing it to a pair enables us to sort easily.
			std::vector<std::pair<std::string, std::string>> params;
			std::transform(
				url.encoded_params().begin(),
				url.encoded_params().end(),
				std::back_inserter(params),
				[](const auto& a) {
					if (a.has_value) {
						return std::pair<std::string, std::string>(a.key, a.value);
					}
					return std::pair<std::string, std::string>(a.key, "");
				});
			std::sort(params.begin(), params.end());
			for (const auto& param : params) {
				// Regarding Query Parameter-based authentication, the S3 documentation says the following:
				// "The Canonical Query String must include all the query parameters from the preceding table except
				// for X-Amz-Signature."
				// Since signatures are not used in generating themselves, exclude them for all authentication types.
				if ("X-Amz-Signature" == param.first) {
					continue;
				}

				// The Query Parameters come from the URL, so they are already URI-encoded.
				result << (first ? "" : "&") << param.first;
				result << '=' << param.second;

				first = false;
			}
		}
		result << '\n';

		// Canonical Headers
		for (const auto& header : parser.get()) {
			if (std::find(signed_headers.begin(), signed_headers.end(), to_lower(header.name_string())) !=
			    signed_headers.end()) {
				sorted_fields.emplace_back(header.name_string().data(), header.name_string().length());
			}
		}

		std::sort(sorted_fields.begin(), sorted_fields.end(), [](const auto& lhs, const auto& rhs) {
			const auto result = std::mismatch(
				lhs.cbegin(),
				lhs.cend(),
				rhs.cbegin(),
				rhs.cend(),
				[](const unsigned char lhs, const unsigned char rhs) { return tolower(lhs) == tolower(rhs); });

			return result.second != rhs.cend() &&
			       (result.first == lhs.cend() || tolower(*result.first) < tolower(*result.second));
		});
		std::string fields_str;
		for (auto& i : sorted_fields) {
			fields_str += i;
			fields_str += ",";
		}
		logging::debug(fields_str);
		for (const auto& field : sorted_fields) {
			auto val = static_cast<std::string>(parser.get().at(boost::string_view(field.data(), field.length())));
			std::string key(field);
			std::transform(key.begin(), key.end(), key.begin(), tolower);
			boost::trim(val);
			result << key << ':';
			result.copyfmt(state);
			result << val << '\n';
		}
		result << "\n";

		sorted_fields.clear();

		// Signed Headers
		for (const auto& hd : signed_headers) {
			sorted_fields.push_back(hd);
		}
		std::sort(sorted_fields.begin(), sorted_fields.end());
		{
			bool first = true;
			for (const auto& i : sorted_fields) {
				result << (first ? "" : ";") << i;
				first = false;
			}
			result.copyfmt(state);
			result << '\n';
		}

		// Hashed Payload
		if (auto req = parser.get().find("X-Amz-Content-SHA256"); req != parser.get().end()) {
			result << req->value();
		}
		else {
			result << "UNSIGNED-PAYLOAD";
		}

		return result.str();
	}

	auto request_is_expired(const std::string& signature_timestamp, const std::string& expiration_time) -> bool
	{
		namespace logging = irods::http::logging;
		// Maximum time request can be valid is 7 days, and here it is being represented in seconds.
		constexpr long long maximum_time_request_can_be_valid_in_seconds = 7 * 24 * 60 * 60;
		constexpr const char* iso_8601_datetime_format = "%Y%m%dT%H%M%SZ";
		try {
			std::chrono::time_point<std::chrono::system_clock> tp;
			std::istringstream is{signature_timestamp};
			// TODO(#154): Replace date::from_stream with std::chrono::from_stream once we get to Clang 19 / gcc 14.
			date::from_stream(is, iso_8601_datetime_format, tp);
			if (is.fail()) {
				// TODO(#151): Should we actually return an error in this case?
				logging::debug(
					"{}: An error occurred when parsing signature timestamp [{}].", __func__, signature_timestamp);
				return true;
			}

			// The expiration time should be a string coming from a query parameter or some other part of a request.
			// It should represent the number of seconds from the time that the request was signed that the
			// signature is valid.
			const auto expiration_in_seconds = std::stoll(expiration_time);
			if (expiration_in_seconds < 0 || expiration_in_seconds > maximum_time_request_can_be_valid_in_seconds) {
				// The expiration time must be a positive integer in the range [0, 604800]. Otherwise, consider the
				// request expired.
				// TODO(#151): Should we actually return an error in this case?
				logging::debug(
					"{}: Expiration time invalid: [{}]. Must be in range [0, 604800].",
					__func__,
					expiration_in_seconds);
				return true;
			}

			if (tp > std::chrono::system_clock::now()) {
				// If the request is from the future, reject it. It's not "expired", but it should not be processed.
				logging::debug("{}: Request was signed at a time in the future: [{}].", __func__, signature_timestamp);
				return true;
			}

			const auto time_of_expiration = tp + std::chrono::seconds{expiration_in_seconds};
			return std::chrono::system_clock::now() > time_of_expiration;
		}
		catch (const std::exception& e) {
			// Failed to interpret expiration timestamp, so, consider it expired.
			logging::debug("{}: Caught exception: {}", __func__, e.what());
		}
		// If we reach here, consider the request expired. Some sort of error has occurred.
		// TODO(#151): Should we actually return an error in this case?
		return true;
	} // request_is_expired
} //namespace

std::optional<std::string> irods::s3::authentication::authenticates(
	const boost::beast::http::request_parser<boost::beast::http::empty_body>& parser,
	const boost::urls::url_view& url)
{
	namespace logging = irods::http::logging;

	std::vector<std::string> auth_fields, credential_fields, signed_headers;

	std::string signature;
	std::string signature_timestamp;

	const auto& parsed_message = parser.get();
	const auto authorization_iter = parsed_message.find("Authorization");
	if (parsed_message.end() == authorization_iter) {
		// If there is no Authorization header in the parsed message, we may be dealing with a presigned URL.
		const auto& params = url.params();

		// The Credential parameter contains the information normally included in the Authorization header.
		const auto credentials_iter = params.find("X-Amz-Credential");
		if (params.end() == credentials_iter) {
			logging::debug("No Authorization header or X-Amz-Credential parameter found.");
			return std::nullopt;
		}
		boost::split(credential_fields, (*credentials_iter).value, boost::is_any_of("/"));

		// The Date query parameter indicates when the request was signed and is required.
		const auto date_iter = params.find("X-Amz-Date");
		if (params.end() == date_iter) {
			logging::debug("No X-Amz-Date query parameter found.");
			return std::nullopt;
		}
		signature_timestamp = (*date_iter).value;

		// Need to make sure the credentials haven't expired yet.
		const auto expiration_iter = params.find("X-Amz-Expires");
		if (params.end() == expiration_iter) {
			logging::debug("No X-Amz-Expires query parameter found.");
			return std::nullopt;
		}
		const auto& expiration_time = (*expiration_iter).value;

		// Make sure the request is not expired. Check the Date + Expire time against current server time. This can
		// happen before or after the signature has been calculated because it will be incorrect if the client tampered
		// with the Date or Expire times.
		if (request_is_expired(signature_timestamp, expiration_time)) {
			logging::debug("Authenticating request failed: Request expired.");
			return std::nullopt;
		}

		// Get the SignedHeaders from the query parameters. This must include at least "host".
		const auto signed_headers_iter = params.find("X-Amz-SignedHeaders");
		if (params.end() == credentials_iter) {
			logging::debug("No X-Amz-SignedHeaders query parameters found.");
			return std::nullopt;
		}
		boost::split(signed_headers, (*signed_headers_iter).value, boost::is_any_of(";"));

		// The actual Signature must be provided so that we can verify the calculated signature.
		const auto signature_iter = params.find("X-Amz-Signature");
		if (params.end() == signature_iter) {
			logging::debug("No X-Amz-Signature query parameter found.");
			return std::nullopt;
		}
		signature = (*signature_iter).value;
	}
	else {
		// should be equal to something like
		// [ 'AWS4-SHA256-HMAC Credential=...', 'SignedHeaders=...', 'Signature=...']
		boost::split(auth_fields, (*authorization_iter).value(), boost::is_any_of(","));

		// Strip the names and such
		for (auto& field : auth_fields) {
			field = field.substr(field.find('=') + 1);
		}

		// Break up the credential field.
		boost::split(credential_fields, auth_fields[0], boost::is_any_of("/"));

		signature = auth_fields[2];

		boost::split(signed_headers, auth_fields[1], boost::is_any_of(";"));

		signature_timestamp = parsed_message.at("X-Amz-Date");
	}

	const auto& access_key_id = credential_fields[0];
	const auto& date = credential_fields[1];
	const auto& region = credential_fields[2];

	const auto canonical_request = canonicalize_request(parser, url, signed_headers);
	logging::debug("========== Canon request ==========\n{}", canonical_request);

	const auto sts = fmt::format(
		"AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
		signature_timestamp,
		date,
		region,
		irods::s3::authentication::hex_encode(irods::s3::authentication::hash_sha_256(canonical_request)));

	logging::debug("======== String to sign ===========\n{}", sts);
	logging::debug("===================================");

	logging::trace("Searching for user with access_key_id={}", access_key_id);
	auto irods_user = irods::s3::authentication::get_iRODS_user(access_key_id);

	if (!irods_user) {
		logging::debug("Authentication Error: No iRODS username mapped to access key ID [{}]", access_key_id);
		return std::nullopt;
	}

	// TODO(#147): Check to make sure that the date is not more than 7 days old. That is the maximum amount of time
	// that a signing key should be valid.
	auto signing_key =
		get_user_signing_key(irods::s3::authentication::get_user_secret_key(access_key_id).value(), date, region);
	auto computed_signature = hex_encode(hmac_sha_256(signing_key, sts));

	logging::debug("Computed: [{}]", computed_signature);

	logging::debug("Actual Signature: [{}]", signature);

	return (computed_signature == signature) ? irods_user : std::nullopt;
} // irods::s3::authentication::authenticates
