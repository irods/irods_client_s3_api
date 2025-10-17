// TODO(#181): The tests within this file MUST be launched from the root of the build
// directory. The implementation uses relative paths to load plugins. This is intentional
// and makes sure tests have full control over what plugin is in use.

#include <catch2/catch.hpp>

#include "irods/s3_api/plugins/bucket_mapping/bucket_mapping.h"
#include "irods/s3_api/plugins/user_mapping/user_mapping.h"

#include <irods/irods_at_scope_exit.hpp>

#include <boost/dll.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>

TEST_CASE("test local file bucket mapping plugin")
{
	boost::dll::shared_library lib{"plugins/bucket_mapping/libirods_s3_api_plugin-bucket_mapping-local_file.so"};

	CHECK(lib.has("bucket_mapping_init"));
	CHECK(lib.has("bucket_mapping_list"));
	CHECK(lib.has("bucket_mapping_collection"));
	CHECK(lib.has("bucket_mapping_close"));
	CHECK(lib.has("bucket_mapping_free"));

	using json = nlohmann::json;

	// The initial user mapping.
	const std::string bucket_1 = "test_bucket_1";
	const std::string collection_1 = "test_collection_1";
	json mapping_config{{bucket_1, collection_1}};

	// Create a file which holds the mapping information.
	constexpr const char* file_path = "./bucket_mapping_test_config.json";
	std::ofstream{file_path} << mapping_config.dump();

	// Initialize the plugin.
	const auto bm_init = lib.get<decltype(bucket_mapping_init)>("bucket_mapping_init");
	REQUIRE(bm_init(json{{"file_path", file_path}}.dump().c_str()) == 0);

	// Get the full listing of mapped buckets.
	bucket_mapping_entry* mappings{};
	std::size_t count = 0;
	const auto bm_list = lib.get<decltype(bucket_mapping_list)>("bucket_mapping_list");
	CHECK(bm_list(&mappings, &count) == 0);
	CHECK(1 == count);
	CHECK(bucket_1 == mappings[0].bucket);
	CHECK(collection_1 == mappings[0].collection);

	const auto bm_free = lib.get<decltype(bucket_mapping_free)>("bucket_mapping_free");
	bm_free(mappings[0].bucket);
	bm_free(mappings[0].collection);
	bm_free(mappings);

	// Show that bucket 1's mapping can be retrieved from the plugin.
	const auto bm_collection = lib.get<decltype(bucket_mapping_collection)>("bucket_mapping_collection");
	char* collection{};
	irods::at_scope_exit free_value{[&collection, &bm_free] { bm_free(collection); }};
	CHECK(bm_collection(bucket_1.c_str(), &collection) == 0);
	CHECK(collection_1 == collection);

	// Add a new bucket mapping to the configuration and show that the plugin updates
	// its state accordingly.

	std::this_thread::sleep_for(std::chrono::seconds{2});

	const std::string bucket_2 = "test_bucket_2";
	const std::string collection_2 = "test_collection_2";
	mapping_config[bucket_2] = collection_2;
	std::ofstream{file_path} << mapping_config.dump();

	bm_free(collection);
	collection = nullptr;
	CHECK(bm_collection(bucket_2.c_str(), &collection) == 0);
	CHECK(collection_2 == collection);

	// Remove bucket 1 from the bucket mapping and show that the plugin updates its
	// state accordingly.

	std::this_thread::sleep_for(std::chrono::seconds{2});

	mapping_config.erase(bucket_1);
	std::ofstream{file_path} << mapping_config.dump();

	bm_free(collection);
	collection = nullptr;
	CHECK(bm_collection(bucket_1.c_str(), &collection) == 0);
	CHECK(nullptr == collection);

	// Shut the plugin down.
	const auto bm_close = lib.get<decltype(bucket_mapping_close)>("bucket_mapping_close");
	CHECK(bm_close() == 0);
}

TEST_CASE("test local file user mapping plugin")
{
	boost::dll::shared_library lib{"plugins/user_mapping/libirods_s3_api_plugin-user_mapping-local_file.so"};

	CHECK(lib.has("user_mapping_init"));
	CHECK(lib.has("user_mapping_irods_username"));
	CHECK(lib.has("user_mapping_s3_secret_key"));
	CHECK(lib.has("user_mapping_close"));
	CHECK(lib.has("user_mapping_free"));

	using json = nlohmann::json;

	// The initial user mapping.
	const std::string alice_access_key_id = "alice";
	constexpr std::string_view alice_secret_key = "apass";
	constexpr std::string_view alice_irods_username = "alice";
	// clang-format off
	json mapping_config{
		{alice_access_key_id, {
			{"secret_key", alice_secret_key},
			{"username", alice_irods_username}
		}}
	};
	// clang-format on

	// Create a file which holds the mapping information.
	constexpr const char* file_path = "./user_mapping_test_config.json";
	std::ofstream{file_path} << mapping_config.dump();

	// Initialize the plugin.
	const auto um_init = lib.get<decltype(user_mapping_init)>("user_mapping_init");
	REQUIRE(um_init(json{{"file_path", file_path}}.dump().c_str()) == 0);

	// Show that alice's information can be retrieved from the plugin.
	const auto um_irods_username = lib.get<decltype(user_mapping_irods_username)>("user_mapping_irods_username");
	const auto um_free = lib.get<decltype(user_mapping_free)>("user_mapping_free");
	char* value{};
	irods::at_scope_exit free_value{[&value, &um_free] { um_free(value); }};
	CHECK(um_irods_username(alice_access_key_id.c_str(), &value) == 0);
	CHECK(alice_irods_username == value);

	um_free(value);
	value = nullptr;
	const auto um_s3_secret_key = lib.get<decltype(user_mapping_s3_secret_key)>("user_mapping_s3_secret_key");
	CHECK(um_s3_secret_key(alice_access_key_id.c_str(), &value) == 0);
	CHECK(alice_secret_key == value);

	// Add a new user mapping to the configuration for bob and show that the plugin updates
	// its state accordingly.

	std::this_thread::sleep_for(std::chrono::seconds{2});

	const std::string bob_access_key_id = "s3_bob";
	constexpr std::string_view bob_secret_key = "bpass";
	constexpr std::string_view bob_irods_username = "bob";
	// clang-format off
	mapping_config[bob_access_key_id] = {
		{"secret_key", bob_secret_key},
		{"username", bob_irods_username}
	};
	// clang-format on
	std::ofstream{file_path} << mapping_config.dump();

	um_free(value);
	value = nullptr;
	CHECK(um_irods_username(bob_access_key_id.c_str(), &value) == 0);
	CHECK(bob_irods_username == value);

	um_free(value);
	value = nullptr;
	CHECK(um_s3_secret_key(bob_access_key_id.c_str(), &value) == 0);
	CHECK(bob_secret_key == value);

	// Remove alice from the user mapping and show that the plugin updates its state
	// accordingly.

	std::this_thread::sleep_for(std::chrono::seconds{2});

	mapping_config.erase(alice_access_key_id);
	std::ofstream{file_path} << mapping_config.dump();

	um_free(value);
	value = nullptr;
	CHECK(um_irods_username(alice_access_key_id.c_str(), &value) == 0);
	CHECK(nullptr == value);

	// Shut the plugin down.
	const auto um_close = lib.get<decltype(user_mapping_close)>("user_mapping_close");
	CHECK(um_close() == 0);
}
