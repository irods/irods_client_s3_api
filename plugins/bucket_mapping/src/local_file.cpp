#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"

#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <boost/algorithm/string.hpp>
#include <date/date.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "hmac_sha256.h"

extern "C" {
#include "sha256.h"
}

namespace
{
	//
	// Global Plugin State
	//

	// In order: last mtime, mutex to control reloads, actual values
	using config_map_value =
		std::tuple<std::filesystem::file_time_type, nlohmann::json, std::unique_ptr<std::shared_mutex>>;

	// Passed json is auth data; returns user or nullopt for failure.
	// Passed file is user mapping config data
	using user_mapping_mode_type =
		std::optional<std::string> (*)(const nlohmann::json&, const std::optional<std::filesystem::path>&);

	// In order: collection name, user_mapping mode, configuration file
	using bucket_mapping_type = std::tuple<std::string, user_mapping_mode_type, std::optional<std::filesystem::path>>;

	// Config storage for some user_mapping modes
	std::unordered_map<std::filesystem::path, config_map_value> g_configs;

	// The path of the configuration file defining various bucket mappings.
	std::filesystem::path g_file_path;

	// Ensures only one thread is allowed to reload the primary bucket_mapping config.
	std::shared_mutex g_mutex;

	// The structure containing the deserialized bucket mappings.
	std::unordered_map<std::string, bucket_mapping_type> g_mappings;
	//	nlohmann::json g_mappings;

	// Forward-declare

	// Any user is anonymous
	std::optional<std::string> map_user_anonymous(
		[[maybe_unused]] const nlohmann::json& _auth_data,
		[[maybe_unused]] const std::optional<std::filesystem::path>& _config_path);

	// Standard s3 auth
	std::optional<std::string> map_user_s3(
		[[maybe_unused]] const nlohmann::json& _auth_data,
		[[maybe_unused]] const std::optional<std::filesystem::path>& _config_path);

	// user_mapping mode strings
	std::unordered_map<std::string, user_mapping_mode_type> g_usermap_modes{
		{"anonymous", map_user_anonymous},
		{"s3_key", map_user_s3}};

	//
	// Helper Functions
	//

	// HMAC stuff
	std::string hmac_sha_256(const std::string_view& key, const std::string_view& data)
	{
		unsigned char result[32];
		unsigned int result_size = 32;
		hmac_sha256(key.data(), key.length(), data.data(), data.length(), result, 32);
		spdlog::trace("HMAC size is {} bytes", result_size);
		return std::string(std::string_view((char*) result, 32));
	}

	std::string hash_sha_256(const std::string_view& data)
	{
		Sha256Context ctx;
		Sha256Initialise(&ctx);
		Sha256Update(&ctx, static_cast<const void*>(data.data()), data.length());
		SHA256_HASH hash;
		Sha256Finalise(&ctx, &hash);
		return std::string((char*) hash.bytes, 32);
	}

	std::string hex_encode(const std::string_view& data)
	{
		std::stringstream s;
		for (size_t i = 0; i < data.length(); i++) {
			s << fmt::format("{:02x}", (unsigned char) data[i]);
		}
		return s.str();
	}

	auto is_bucket_mapping_config_valid(const std::string& _config) -> bool
	{
		spdlog::debug("{}: Validating configuration file. {}", __func__, _config);

		return true;
		/*
		        namespace jsonschema = jsoncons::jsonschema;

		        const auto config = jsoncons::json::parse(_config);

		        auto schema = jsoncons::json::parse(R"({
		    "$schema": "https://json-schema.org/draft/2020-12/schema",
		    "$id": "https://schemas.irods.org/irods-s3-api/bucket-mapping-plugin-config.json",
		    "type": "object",
		    "patternProperties": {
		        "^.+$": {"type": "string"}
		    },
		    "additionalProperties": false
		})");
		        const auto compiled = jsonschema::make_json_schema(std::move(schema));

		        jsoncons::json_decoder<jsoncons::ojson> decoder;
		        compiled.validate(config, decoder);
		        const auto json_result = decoder.get_result();

		        if (!json_result.empty()) {
		            std::ostringstream out;
		            out << pretty_print(json_result);
		            spdlog::error("{}: Configuration failed validation: {}", __func__, out.str());
		            return false;
		        }

		        spdlog::debug("{}: Configuration passed validation.", __func__);
		        return true;
		*/
	} // is_bucket_mapping_config_valid

	auto load_bucket_mapping() -> void
	{
		static std::filesystem::file_time_type last_file_path_write;

		auto new_mtime = std::filesystem::last_write_time(g_file_path);
		if (new_mtime == last_file_path_write) {
			spdlog::trace("{}: Mapping file has not been modified, skipping update.", __func__);
			return;
		}

		spdlog::trace("{}: Mapping file modified, updating internal state.", __func__);

		std::ifstream file{g_file_path};
		if (!file) {
			throw std::runtime_error{fmt::format("Could not open file [{}].", g_file_path.c_str())};
		}

		auto mappings = nlohmann::json::parse(file);

		if (!is_bucket_mapping_config_valid(mappings.dump())) {
			return;
		}

		decltype(g_mappings) g_mappings_copy;

		auto it_proxy = mappings.items();
		// Load bucket mappings into map
		std::transform(
			it_proxy.begin(),
			it_proxy.end(),
			std::inserter(g_mappings_copy, g_mappings_copy.end()),
			[](const std::decay_t<decltype(*mappings.items().begin())>& entry) {
				return std::make_pair(
					// Bucket name
					entry.key(),
					std::make_tuple(
						// iRODS logical path
						entry.value().at("path").get<std::string>(),
						// User mapping mode
						g_usermap_modes.at(entry.value().at("user_mapping").at("mode").get<std::string>()),
						// Optional config file for user_mapping mode
						entry.value().at("user_mapping").contains("config_file")
							? std::optional<
								  std::filesystem::
									  path>{std::in_place, entry.value().at("user_mapping").at("config_file").get<std::string>()}
							: std::nullopt));
			});

		last_file_path_write = new_mtime;

		decltype(g_configs) g_configs_copy;

		// Force reload all per-file configs
		for (const auto& mapping : g_mappings_copy) {
			if (const auto& filename = std::get<2>(mapping.second); filename) {
				std::ifstream file{filename.value()};
				if (!file) {
					throw std::runtime_error{fmt::format("Could not open file [{}].", g_file_path.c_str())};
				}
				g_configs_copy.emplace(
					std::piecewise_construct,
					std::forward_as_tuple(filename.value()),
					std::forward_as_tuple(
						std::filesystem::last_write_time(filename.value()),
						nlohmann::json::parse(file),
						std::make_unique<std::shared_mutex>()));
			}
		}

		// Only overwrite globals if everything succeeded
		g_mappings = std::move(g_mappings_copy);
		g_configs = std::move(g_configs_copy);
	} // load_bucket_mapping

	auto reload_usermap_configuration_if_modified(const std::filesystem::path _path) -> void
	{
		try {
			// Acquire exclusive lock on per-file mutex stored in g_configs.
			// If fail, do not reload.
			if (std::unique_lock lock{*std::get<2>(g_configs.at(_path)), std::try_to_lock}; lock) {
				auto new_mtime = std::filesystem::last_write_time(_path);
				if (new_mtime == std::get<0>(g_configs.at(_path))) {
					spdlog::debug("Usermap config {} is unmodified; skipping reload.", _path.string());
					return;
				}
				std::ifstream file{_path};

				if (!file) {
					throw std::runtime_error{fmt::format("Could not open file [{}].", g_file_path.c_str())};
				}
				std::get<1>(g_configs.at(_path)) = nlohmann::json::parse(file);
				std::get<0>(g_configs.at(_path)) = new_mtime;
			}
		}
		catch (const std::exception& e) {
			spdlog::error("{}: {}", __func__, e.what());
		}
	} // reload_usermap_configuration_if_modified

	auto reload_configuration_if_modified() -> void
	{
		try {
			if (std::unique_lock lock{g_mutex, std::try_to_lock}; lock) {
				load_bucket_mapping();
			}
		}
		catch (const std::exception& e) {
			spdlog::error("{}: {}", __func__, e.what());
		}
	} // reload_configuration_if_modified

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
		spdlog::debug("date time component is {}", date);
		auto date_key = hmac_sha_256(std::string("AWS4").append(secret_key), date);
		auto date_region_key = hmac_sha_256(date_key, region);
		auto date_region_service_key = hmac_sha_256(date_region_key, "s3");
		return hmac_sha_256(date_region_service_key, "aws4_request");
	}

	// TODO we can improve performance by reusing the same stringstream where possible.

	// Turn the url into the 'canon form'
	std::string canonicalize_url_segments(const std::vector<std::string>& segments)
	{
		std::stringstream result;
		for (const auto& i : segments) {
			result << '/' << uri_encode(i);
		}
		return result.str();
	}

	std::string to_lower(const std::string_view sv)
	{
		std::string r;
		for (const auto& i : sv) {
			r.push_back(tolower(i));
		}
		return r;
	}
	std::string canonicalize_request(const nlohmann::json& auth_json, const std::multiset<std::string>& signed_headers)
	{
		// At various points the signature process wants various fields to be sorted.
		// so reusing this can at least avoid some of the duplicate allocations and such
		std::vector<std::string_view> sorted_fields;

		std::stringstream result;

		std::ios state(nullptr);
		state.copyfmt(result);

		// HTTP Verb
		// Caller guarantees existence, so no extra check needed here
		result << auth_json["verb"].get<std::string>() << '\n';
		result.copyfmt(result); // re store former formatting

		// Canonical URI
		result << canonicalize_url_segments(auth_json["url_segments"].get<std::vector<std::string>>()) << '\n';

		// Canonical Query String
		std::map<std::string, std::string> params;
		auto it_proxy = auth_json["url_params"].items();

		// URL-encode
		std::transform(
			it_proxy.begin(),
			it_proxy.end(),
			std::inserter(params, params.end()),
			[](const std::decay_t<decltype(*it_proxy.begin())>& entry) {
				if (entry.value().is_null()) {
					return std::pair<std::string, std::string>(uri_encode(entry.key()), "");
				}
				else {
					return std::pair<std::string, std::string>(
						uri_encode(entry.key()), uri_encode(entry.value().get<std::string>()));
				}
			});

		// Regarding Query Parameter-based authentication, the S3 documentation says the following:
		// "The Canonical Query String must include all the query parameters from the preceding table except
		// for X-Amz-Signature."
		// Since signatures are not used in generating themselves, exclude them for all authentication types.
		result << std::accumulate(params.begin(), params.end(), std::string{}, [](auto&& acc, const auto& param) {
			if (param.first == "X-Amz-Signature") {
				return std::move(acc);
			}
			if (acc == "") {
				return std::move(acc) + param.first + '=' + param.second;
			}
			return std::move(acc) + '&' + param.first + '=' + param.second;
		});

		result << '\n';

		// Canonical Headers
		for (auto& [key, val] : auth_json["headers"].items()) {
			if (std::find(signed_headers.begin(), signed_headers.end(), to_lower(key)) != signed_headers.end()) {
				sorted_fields.push_back(key);
			}
		}

		std::sort(sorted_fields.begin(), sorted_fields.end(), [](const auto& lhs, const auto& rhs) {
			return std::lexicographical_compare(
				lhs.cbegin(), lhs.cend(), rhs.cbegin(), rhs.cend(), [](const auto& lhs_elem, const auto& rhs_elem) {
					return tolower(lhs_elem) < tolower(rhs_elem);
				});
		});

		std::string fields_str = std::accumulate(
			sorted_fields.begin(), sorted_fields.end(), std::string{}, [](auto&& accum, const auto& elem) {
				return accum == std::string{""} ? std::string{elem} : std::move(accum) + ',' + std::string{elem};
			});

		spdlog::debug("fields str is {}", fields_str);

		result << std::accumulate(
			sorted_fields.begin(), sorted_fields.end(), std::string{}, [&auth_json](auto&& accum, const auto& elem) {
				return std::move(accum) + to_lower(elem) + ':' +
			           auth_json["headers"][std::string(elem)].get<std::string>() + '\n';
			});

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
		if (auto req = auth_json["headers"].find("X-Amz-Content-SHA256"); req != auth_json["headers"].end()) {
			result << req.value().get<std::string>();
		}
		else {
			result << "UNSIGNED-PAYLOAD";
		}

		spdlog::debug("Result string is {}", result.str());
		return result.str();
	}

	auto request_is_expired(const std::string& signature_timestamp, const std::string& expiration_time) -> bool
	{
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
				spdlog::debug(
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
				spdlog::debug(
					"{}: Expiration time invalid: [{}]. Must be in range [0, 604800].",
					__func__,
					expiration_in_seconds);
				return true;
			}

			if (tp > std::chrono::system_clock::now()) {
				// If the request is from the future, reject it. It's not "expired", but it should not be processed.
				spdlog::debug("{}: Request was signed at a time in the future: [{}].", __func__, signature_timestamp);
				return true;
			}

			const auto time_of_expiration = tp + std::chrono::seconds{expiration_in_seconds};
			return std::chrono::system_clock::now() > time_of_expiration;
		}
		catch (const std::exception& e) {
			// Failed to interpret expiration timestamp, so, consider it expired.
			spdlog::debug("{}: Caught exception: {}", __func__, e.what());
		}
		// If we reach here, consider the request expired. Some sort of error has occurred.
		// TODO(#151): Should we actually return an error in this case?
		return true;
	} // request_is_expired

	std::optional<std::string> authenticates(const nlohmann::json& auth_json, const std::filesystem::path& usermap_path)
	{
		std::vector<std::string> auth_fields, credential_fields;
		std::multiset<std::string> signed_headers;

		std::string signature;
		std::string signature_timestamp;

		if (!auth_json.contains("headers") || !auth_json.contains("verb") || !auth_json.contains("url_params") ||
		    !auth_json.contains("url_segments"))
		{
			spdlog::debug("Malformed auth_json: {}", auth_json.dump());
			return std::nullopt;
		}

		spdlog::debug("auth_json: {}", auth_json.dump());

		const auto& headers = auth_json["headers"];
		const auto authorization_iter = headers.find("Authorization");
		if (headers.end() == authorization_iter) {
			// If there is no Authorization header in the parsed message, we may be dealing with a presigned URL.
			const auto& params = auth_json["params"];

			// The Credential parameter contains the information normally included in the Authorization header.
			const auto credentials_iter = params.find("X-Amz-Credential");
			if (params.end() == credentials_iter) {
				spdlog::debug("No Authorization header or X-Amz-Credential parameter found.");
				return std::nullopt;
			}
			boost::split(credential_fields, credentials_iter.value().get<std::string>(), boost::is_any_of("/"));

			// The Date query parameter indicates when the request was signed and is required.
			const auto date_iter = params.find("X-Amz-Date");
			if (params.end() == date_iter) {
				spdlog::debug("No X-Amz-Date query parameter found.");
				return std::nullopt;
			}
			signature_timestamp = date_iter.value();

			// Need to make sure the credentials haven't expired yet.
			const auto expiration_iter = params.find("X-Amz-Expires");
			if (params.end() == expiration_iter) {
				spdlog::debug("No X-Amz-Expires query parameter found.");
				return std::nullopt;
			}
			const auto& expiration_time = expiration_iter.value();

			// Make sure the request is not expired. Check the Date + Expire time against current server time. This can
			// happen before or after the signature has been calculated because it will be incorrect if the client
			// tampered with the Date or Expire times.
			if (request_is_expired(signature_timestamp, expiration_time)) {
				spdlog::debug("Authenticating request failed: Request expired.");
				return std::nullopt;
			}

			// Get the SignedHeaders from the query parameters. This must include at least "host".
			const auto signed_headers_iter = params.find("X-Amz-SignedHeaders");
			if (params.end() == credentials_iter) {
				spdlog::debug("No X-Amz-SignedHeaders query parameters found.");
				return std::nullopt;
			}
			boost::split(signed_headers, signed_headers_iter.value().get<std::string>(), boost::is_any_of(";"));

			// The actual Signature must be provided so that we can verify the calculated signature.
			const auto signature_iter = params.find("X-Amz-Signature");
			if (params.end() == signature_iter) {
				spdlog::debug("No X-Amz-Signature query parameter found.");
				return std::nullopt;
			}
			signature = signature_iter.value();
		}
		else {
			// should be equal to something like
			// [ 'AWS4-HMAC-SHA256 Credential=...', 'SignedHeaders=...', 'Signature=...']
			boost::split(auth_fields, authorization_iter.value().get<std::string>(), boost::is_any_of(","));

			// Strip the names and such
			for (auto& field : auth_fields) {
				field = field.substr(field.find('=') + 1);
			}

			// Break up the credential field.
			boost::split(credential_fields, auth_fields[0], boost::is_any_of("/"));

			signature = auth_fields[2];

			boost::split(signed_headers, auth_fields[1], boost::is_any_of(";"));

			signature_timestamp = headers.at("X-Amz-Date");
		}

		const auto& access_key_id = credential_fields[0];
		const auto& date = credential_fields[1];
		const auto& region = credential_fields[2];

		const auto canonical_request = canonicalize_request(auth_json, signed_headers);
		spdlog::debug("========== Canon request ==========\n{}", canonical_request);

		const auto sts = fmt::format(
			"AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
			signature_timestamp,
			date,
			region,
			hex_encode(hash_sha_256(canonical_request)));

		spdlog::debug("======== String to sign ===========\n{}", sts);
		spdlog::debug("===================================");

		spdlog::trace("Searching for user with access_key_id={}", access_key_id);

		// Paths are guaranteed to be in g_configs, since the keys are passed in from
		// g_mappings, which loads g_configs on load in load_bucket_mapping
		const nlohmann::json& config_json = std::get<1>(g_configs.at(usermap_path));
		std::string irods_user, secret_key;

		if (config_json.contains(access_key_id) && config_json[access_key_id].contains("username") &&
		    config_json[access_key_id].contains("secret_key"))
		{
			irods_user = config_json[access_key_id]["username"];
			secret_key = config_json[access_key_id]["secret_key"];
		}
		else {
			spdlog::debug("Authentication Error: No iRODS username mapped to access key ID [{}]", access_key_id);
			return std::nullopt;
		}

		// TODO(#147): Check to make sure that the date is not more than 7 days old. That is the maximum amount of time
		// that a signing key should be valid.
		auto signing_key = get_user_signing_key(secret_key, date, region);
		auto computed_signature = hex_encode(hmac_sha_256(signing_key, sts));

		spdlog::debug("Computed: [{}]", computed_signature);

		spdlog::debug("Actual Signature: [{}]", signature);

		return (computed_signature == signature) ? (std::optional<std::string>(std::in_place, irods_user))
		                                         : std::nullopt;
	} // authenticates

	std::optional<std::string> map_user_anonymous(
		[[maybe_unused]] const nlohmann::json& _auth_data,
		[[maybe_unused]] const std::optional<std::filesystem::path>& _config_path)
	{
		return std::optional<std::string>(std::in_place, "anonymous");
	}

	std::optional<std::string> map_user_s3(
		const nlohmann::json& _auth_data,
		const std::optional<std::filesystem::path>& _config_path)
	{
		if (!_config_path) {
			// Config is required.
			spdlog::error("Missing config file path for s3_key config.");
			return std::nullopt;
		}
		return authenticates(_auth_data, *_config_path);
	}
} // anonymous namespace

auto bucket_mapping_init(const char* _json) -> int
{
	if (!_json) {
		spdlog::error("{}: Received null pointer.", __func__);
		return 1;
	}

	try {
		const auto config = nlohmann::json::parse(_json);
		const auto iter = config.find("file_path");
		if (iter == std::end(config)) {
			spdlog::error("{}: Could not find [file_path] property in configuration.", __func__);
			return 1;
		}
		g_file_path = iter->get<std::string>();
		spdlog::debug("{}: file_path = [{}]", __func__, g_file_path.c_str());

		load_bucket_mapping();

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // bucket_mapping_init

auto bucket_mapping_list(bucket_mapping_entry_t** _buckets, size_t* _size) -> int
{
	try {
		if (!_buckets || !_size) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}

		*_buckets = nullptr;
		*_size = 0;

		reload_configuration_if_modified();

		std::shared_lock read_lock{g_mutex};

		const auto entry_count = g_mappings.size();
		if (0 == entry_count) {
			return 0;
		}

		// Allocate an array large enough to hold all bucket mappings.
		const auto allocation_size = sizeof(bucket_mapping_entry) * entry_count;
		auto* mappings = static_cast<bucket_mapping_entry*>(std::malloc(allocation_size));
		if (!mappings) {
			spdlog::error("{}: Could not allocate memory for bucket mappings.", __func__);
			return 1;
		}
		std::memset(mappings, 0, allocation_size);

		// Fill the bucket mapping array.
		std::size_t i = 0;
		bool dealloc_memory = false;
		for (const auto& mapping : g_mappings) {
			auto* p = strdup(mapping.first.c_str());
			if (!p) {
				dealloc_memory = true;
				spdlog::error("{}: Could not allocate memory for bucket name.", __func__);
				break;
			}
			mappings[i].bucket = p;
			spdlog::debug("{}: (mapping-{}) bucket name = [{}]", __func__, i, p);

			p = strdup(std::get<0>(mapping.second).c_str());
			if (!p) {
				dealloc_memory = true;
				spdlog::error("{}: Could not allocate memory for collection path.", __func__);
				break;
			}
			mappings[i].collection = p;
			spdlog::debug("{}: (mapping-{}) collection path = [{}]", __func__, i, p);

			++i;
		}

		if (dealloc_memory) {
			for (std::size_t i = 0; i < entry_count; ++i) {
				std::free(mappings[i].bucket);
				std::free(mappings[i].collection);
			}
			std::free(mappings);
			return 1;
		}

		*_buckets = mappings;
		*_size = entry_count;

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // bucket_mapping_list

auto bucket_mapping_collection(const char* _bucket, char** _collection) -> int
{
	try {
		if (!_bucket || !_collection) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}

		*_collection = nullptr;

		reload_configuration_if_modified();

		std::shared_lock read_lock{g_mutex};

		if (const auto iter = g_mappings.find(_bucket); iter != std::end(g_mappings)) {
			auto* p = strdup(std::get<0>(iter->second).c_str());
			if (!p) {
				spdlog::error("{}: Could not allocate memory for collection path.", __func__);
				return 1;
			}
			*_collection = p;
		}

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // bucket_mapping_collection

int bucket_mapping_map_user(const char* _bucket, const char* _auth_json, char** _user)
{
	try {
		if (!_bucket || !_user) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}
		nlohmann::json auth_json{};
		if (_auth_json) {
			auth_json = nlohmann::json::parse(_auth_json);
		}

		*_user = nullptr;

		reload_configuration_if_modified();

		std::shared_lock read_lock{g_mutex};

		if (const auto iter = g_mappings.find(_bucket); iter != std::end(g_mappings)) {
			// Empty lock, as config is optional
			std::shared_lock<std::shared_mutex> usermap_config_read_lock;
			if (std::get<2>(iter->second)) {
				reload_usermap_configuration_if_modified(*std::get<2>(iter->second));
				usermap_config_read_lock = std::shared_lock{*std::get<2>(g_configs.at(*std::get<2>(iter->second)))};
			}

			const auto& optional_username = (std::get<1>(iter->second))(auth_json, std::get<2>(iter->second));
			if (optional_username) {
				auto* p = strdup(optional_username->c_str());
				if (!p) {
					spdlog::error("{}: Could not allocate memory for collection path.", __func__);
					return 1;
				}
				*_user = p;
			}
		}

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
}

auto bucket_mapping_close() -> int
{
	return 0;
} // bucket_mapping_close

auto bucket_mapping_free(void* _data) -> void
{
	std::free(_data);
} // bucket_mapping_free
