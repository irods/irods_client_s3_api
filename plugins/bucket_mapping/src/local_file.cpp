#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"

#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
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

	// The path of the configuration file defining various bucket mappings.
	std::filesystem::path g_file_path;

	// The structure containing the deserialized bucket mappings.
	std::shared_mutex g_mutex;

	// Ensures only one thread is allowed to reload the mappings.
	nlohmann::json g_mappings;

	//
	// Helper Functions
	//

	auto is_bucket_mapping_config_valid(const std::string& _config) -> bool
	{
		spdlog::debug("{}: Validating configuration file.", __func__);

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

		g_mappings = std::move(mappings);
		last_file_path_write = new_mtime;
	} // load_bucket_mapping

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
		for (auto&& iter : g_mappings.items()) {
			auto* p = strdup(iter.key().c_str());
			if (!p) {
				dealloc_memory = true;
				spdlog::error("{}: Could not allocate memory for bucket name.", __func__);
				break;
			}
			mappings[i].bucket = p;
			spdlog::debug("{}: (mapping-{}) bucket name = [{}]", __func__, i, p);

			p = strdup(iter.value().get_ref<const std::string&>().c_str());
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
			auto* p = strdup(iter->get_ref<const std::string&>().c_str());
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

auto bucket_mapping_close() -> int
{
	return 0;
} // bucket_mapping_close

auto bucket_mapping_free(void* _data) -> void
{
	std::free(_data);
} // bucket_mapping_free
