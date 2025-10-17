#include "irods/s3_api/plugins/user_mapping/user_mapping.h"

#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <shared_mutex>
#include <stdexcept>
#include <string>

namespace
{
	//
	// Global Plugin State
	//

	// The path of the configuration file defining various user mappings.
	std::filesystem::path g_file_path;

	// The structure containing the deserialized user mappings.
	nlohmann::json g_mappings;

	// Ensures only one thread is allowed to reload the mappings.
	std::shared_mutex g_mutex;

	//
	// Helper Functions
	//

	auto is_user_mapping_config_valid(const std::string& _config) -> bool
	{
		spdlog::debug("{}: Validating configuration file.", __func__);

		namespace jsonschema = jsoncons::jsonschema;

		const auto config = jsoncons::json::parse(_config);

		auto schema = jsoncons::json::parse(R"({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://schemas.irods.org/irods-s3-api/user-mapping-plugin-config.json",
    "type": "object",
    "patternProperties": {
        "^.+$": {
            "type": "object",
            "properties": {
                "secret_key": {"type": "string"},
                "username": {"type": "string"}
            },
            "required": [
                "secret_key",
                "username"
            ]
        }
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
	} // is_user_mapping_config_valid

	auto load_user_mapping() -> void
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
		if (!is_user_mapping_config_valid(mappings.dump())) {
			return;
		}

		g_mappings = std::move(mappings);
		last_file_path_write = new_mtime;
	} // load_user_mapping

	auto reload_configuration_if_modified() -> void
	{
		// If there is an exception while updating, catch so we can still
		// provide matches with our current good state.
		try {
			// Only allow one thread to run update at a time.
			if (std::unique_lock lock{g_mutex, std::try_to_lock}; lock) {
				load_user_mapping();
			}
		}
		catch (const std::exception& e) {
			spdlog::error("{}: {}", __func__, e.what());
		}
	} // reload_configuration_if_modified
} // anonymous namespace

auto user_mapping_init(const char* _json) -> int
{
	try {
		if (!_json) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}

		const auto config = nlohmann::json::parse(_json);
		const auto iter = config.find("file_path");
		if (iter == std::end(config)) {
			spdlog::error("{}: Could not find [file_path] property in configuration.", __func__);
			return 1;
		}
		g_file_path = iter->get<std::string>();
		spdlog::debug("{}: file_path = [{}]", __func__, g_file_path.c_str());

		load_user_mapping();

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // user_mapping_init

auto user_mapping_irods_username(const char* _s3_access_key_id, char** _irods_username) -> int
{
	try {
		if (!_s3_access_key_id || !_irods_username) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}

		spdlog::debug(
			"{}: Fetching iRODS username associated with S3 access key ID [{}].", __func__, _s3_access_key_id);

		*_irods_username = nullptr;

		reload_configuration_if_modified();

		std::shared_lock read_profile_list_lock{g_mutex};

		for (const auto& [k, v] : g_mappings.items()) {
			if (k == _s3_access_key_id) {
				const auto& username = v.at("username").get_ref<const std::string&>();
				spdlog::debug(
					"{}: Found iRODS username [{}] associated with S3 access key ID [{}].",
					__func__,
					username,
					_s3_access_key_id);
				auto* p = strdup(username.c_str());
				if (!p) {
					spdlog::error("{}: Could not allocate memory for iRODS username.", __func__);
					return 1;
				}
				*_irods_username = p;
				break;
			}
		}

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // user_mapping_irods_username

auto user_mapping_s3_secret_key(const char* _s3_access_key_id, char** _s3_secret_key) -> int
{
	try {
		if (!_s3_access_key_id || !_s3_secret_key) {
			spdlog::error("{}: Received null pointer.", __func__);
			return 1;
		}

		spdlog::debug("{}: Fetching S3 secret key associated with S3 access key ID [{}].", __func__, _s3_access_key_id);

		*_s3_secret_key = nullptr;

		reload_configuration_if_modified();

		std::shared_lock read_profile_list_lock{g_mutex};

		for (const auto& [k, v] : g_mappings.items()) {
			if (k == _s3_access_key_id) {
				spdlog::debug(
					"{}: Found S3 secret key associated with S3 access key ID [{}].", __func__, _s3_access_key_id);
				auto* p = strdup(v.at("secret_key").get_ref<const std::string&>().c_str());
				if (!p) {
					spdlog::error("{}: Could not allocate memory for S3 secret key.", __func__);
					return 1;
				}
				*_s3_secret_key = p;
				break;
			}
		}

		return 0;
	}
	catch (const std::exception& e) {
		spdlog::error("{}: {}", __func__, e.what());
		return 1;
	}
} // user_mapping_s3_secret_key

auto user_mapping_close() -> int
{
	return 0;
} // user_mapping_close

auto user_mapping_free(void* _data) -> void
{
	std::free(_data);
} // user_mapping_free
