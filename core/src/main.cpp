#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/transport.hpp"
#include "irods/private/s3_api/version.hpp"
#include "irods/private/s3_api/configuration.hpp"

#include <irods/connection_pool.hpp>
#include <irods/fully_qualified_username.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/rodsClient.h>

#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
#  include <irods/authenticate.h>
#  include <irods/irods_auth_constants.hpp> // For AUTH_PASSWORD_KEY.
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5

#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>
#include <boost/dll.hpp>
#include <boost/program_options.hpp>
#include <boost/url/parse.hpp>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#include <boost/process.hpp>
#pragma clang diagnostic pop

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <jsoncons/json.hpp>
#include <jsoncons_ext/jsonschema/jsonschema.hpp>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// __has_feature is a Clang specific feature.
// The preprocessor code below exists so that other compilers can be used (e.g. GCC).
#ifndef __has_feature
#  define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
// Defines default options for running the S3 API with Address Sanitizer enabled.
// This is a convenience function which allows the S3 API to start without needing the
// administrator to specify options via environment variables.
extern "C" const char* __asan_default_options()
{
	// See root CMakeLists.txt file for definition.
	return IRODS_ADDRESS_SANITIZER_DEFAULT_OPTIONS;
} // __asan_default_options
#endif

// clang-format off
namespace beast   = boost::beast; // from <boost/beast.hpp>
namespace net     = boost::asio;  // from <boost/asio.hpp>
namespace po      = boost::program_options;
namespace fs      = std::filesystem;
namespace logging = irods::http::logging;

using json = nlohmann::json;
using tcp  = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// Accepts incoming connections and launches the sessions.
class listener : public std::enable_shared_from_this<listener>
{
  public:
	listener(net::io_context& ioc, const tcp::endpoint& endpoint, const json& _config)
		: ioc_{ioc}
		, acceptor_{net::make_strand(ioc)}
		, max_body_size_{_config.at(json::json_pointer{"/s3_server/requests/max_size_of_request_body_in_bytes"})
	                         .get<int>()}
		, timeout_in_secs_{_config.at(json::json_pointer{"/s3_server/requests/timeout_in_seconds"}).get<int>()}
	{
		acceptor_.open(endpoint.protocol());
		acceptor_.set_option(net::socket_base::reuse_address(true));
		acceptor_.bind(endpoint);
		acceptor_.listen(net::socket_base::max_listen_connections);
	} // listener (constructor)

	// Start accepting incoming connections.
	auto run() -> void
	{
		do_accept();
	} // run

  private:
	auto do_accept() -> void
	{
		// The new connection gets its own strand
		acceptor_.async_accept(
			net::make_strand(ioc_), beast::bind_front_handler(&listener::on_accept, shared_from_this()));
	} // do_accept

	auto on_accept(beast::error_code ec, tcp::socket socket) -> void
	{
		if (ec) {
			irods::fail(ec, "accept");
			//return; // To avoid infinite loop
		}
		else {
			// Create the session and run it
			std::make_shared<irods::http::session>(std::move(socket), max_body_size_, timeout_in_secs_)
				->run();
		}

		// Accept another connection
		do_accept();
	} // on_accept

	net::io_context& ioc_;
	tcp::acceptor acceptor_;
	const int max_body_size_;
	const int timeout_in_secs_;
}; // class listener

auto print_version_info() -> void
{
	namespace version = irods::s3::version;
	const std::string_view sha = version::sha;
	constexpr auto sha_size = 7;
	fmt::print("{} v{}-{}\n", version::binary_name, version::api_version, sha.substr(0, sha_size));
} // print_version_info

constexpr auto default_jsonschema() -> std::string_view
{
	// clang-format on
	return R"({
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://schemas.irods.org/irods-s3-api/schema.json",
    "type": "object",
    "properties": {
        "s3_server": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "pattern": "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"
                },
                "port": {
                    "type": "integer"
                },
                "log_level": {
                    "enum": [
                        "trace",
                        "debug",
                        "info",
                        "warn",
                        "error",
                        "critical"
                    ]
                },
                "bucket_mapping": {
                    "type": "object",
                    "properties": {
                        "plugin_path": {
                            "type": "string"
                        },
                        "configuration": {
                            "type": "object"
                        }
                    },
                    "required": [
                        "plugin_path",
                        "configuration"
                    ]
                },
                "user_mapping": {
                    "type": "object",
                    "properties": {
                        "plugin_path": {
                            "type": "string"
                        },
                        "configuration": {
                            "type": "object"
                        }
                    },
                    "required": [
                        "plugin_path",
                        "configuration"
                    ]
                },
                "region": {
                    "type": "string"
                },
                "multipart_upload_part_files_directory": {
                    "type": "string"
                },
                "requests": {
                    "type": "object",
                    "properties": {
                        "threads": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "max_size_of_request_body_in_bytes": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "timeout_in_seconds": {
                            "type": "integer",
                            "minimum": 1
                        }
                    },
                    "required": [
                        "threads",
                        "max_size_of_request_body_in_bytes",
                        "timeout_in_seconds"
                    ]
                },
                "background_io": {
                    "type": "object",
                    "properties": {
                        "threads": {
                            "type": "integer",
                            "minimum": 1
                        }
                    },
                    "required": [
                        "threads"
                    ]
                }
            },
            "required": [
                "host",
                "port",
                "bucket_mapping",
                "user_mapping",
                "region",
                "multipart_upload_part_files_directory",
                "requests",
                "background_io"
            ]
        },
        "irods_client": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string"
                },
                "port": {
                    "type": "integer"
                },
                "zone": {
                    "type": "string"
                },
                "tls": {
                    "type": "object",
                    "properties": {
                        "client_server_policy": {
                            "enum": [
                                "CS_NEG_REFUSE",
                                "CS_NEG_DONT_CARE",
                                "CS_NEG_REQUIRE"
                            ]
                        },
                        "ca_certificate_file": {
                            "type": "string"
                        },
                        "certificate_chain_file": {
                            "type": "string"
                        },
                        "dh_params_file": {
                            "type": "string"
                        },
                        "verify_server": {
                            "enum": [
                                "none",
                                "cert",
                                "hostname"
                            ]
                        },
                        "client_server_negotiation": {
                            "type": "string"
                        },
                        "encryption_algorithm": {
                            "type": "string"
                        },
                        "encryption_key_size": {
                            "type": "integer"
                        },
                        "encryption_hash_rounds": {
                            "type": "integer"
                        },
                        "encryption_salt_size": {
                            "type": "integer"
                        }
                    },
                    "required": [
                        "client_server_policy",
                        "ca_certificate_file",
                        "dh_params_file",
                        "verify_server",
                        "client_server_negotiation",
                        "encryption_algorithm",
                        "encryption_key_size",
                        "encryption_hash_rounds",
                        "encryption_salt_size"
                    ]
                },
                "enable_4_2_compatibility": {
                    "type": "boolean"
                },
                "proxy_admin_account": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string"
                        },
                        "password": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "username",
                        "password"
                    ]
                },
                "connection_pool": {
                    "type": "object",
                    "properties": {
                        "size": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "refresh_timeout_in_seconds": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "max_retrievals_before_refresh": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "refresh_when_resource_changes_detected": {
                            "type": "boolean"
                        }
                    },
                    "required": [
                        "size"
                    ]
                },
                "resource": {
                    "type": "string"
                },
                "put_object_buffer_size_in_bytes": {
                    "type": "integer",
                    "minimum": 1
                },
                "get_object_buffer_size_in_bytes": {
                    "type": "integer",
                    "minimum": 1
                }
            },
            "required": [
                "host",
                "port",
                "zone",
                "enable_4_2_compatibility",
                "proxy_admin_account",
                "connection_pool",
                "resource",
                "put_object_buffer_size_in_bytes",
                "get_object_buffer_size_in_bytes"
            ]
        }
    },
    "required": [
        "s3_server",
        "irods_client"
    ]
}
)";
	// clang-format on
} // default_jsonschema

auto print_configuration_template() -> void
{
	// clang-format off
	fmt::print(R"({{
    "s3_server": {{
        "host": "0.0.0.0",
        "port": 9000,
        "log_level": "info",

        "bucket_mapping": {{
            "plugin_path": "/path/to/plugin.so",
            "configuration": {{
                "file_path": "/path/to/mapping_file.json"
            }}
        }},

        "user_mapping": {{
            "plugin_path": "/path/to/plugin.so",
            "configuration": {{
                "file_path": "/path/to/mapping_file.json"
            }}
        }},

        "region": "us-east-1",

        "multipart_upload_part_files_directory": "/tmp",

        "requests": {{
            "threads": 3,
            "max_size_of_request_body_in_bytes": 8388608,
            "timeout_in_seconds": 30
        }},

        "background_io": {{
            "threads": 6
        }}
    }},

    "irods_client": {{
        "host": "<string>",
        "port": 1247,
        "zone": "<string>",

        "tls": {{
            "client_server_policy": "CS_NEG_REFUSE",
            "ca_certificate_file": "<string>",
            "certificate_chain_file": "<string>",
            "dh_params_file": "<string>",
            "verify_server": "<string>",
            "client_server_negotiation": "request_server_negotiation",
            "encryption_algorithm": "AES-256-CBC",
            "encryption_key_size": 32,
            "encryption_hash_rounds": 16,
            "encryption_salt_size": 8
        }},

        "enable_4_2_compatibility": false,

        "proxy_admin_account": {{
            "username": "<string>",
            "password": "<string>"
        }},

        "connection_pool": {{
            "size": 6,
            "refresh_timeout_in_seconds": 600,
            "max_retrievals_before_refresh": 16,
            "refresh_when_resource_changes_detected": true
        }},

        "resource": "<string>",

        "put_object_buffer_size_in_bytes": 8192,
        "get_object_buffer_size_in_bytes": 8192
    }}
}}
)");
	// clang-format on
} // print_configuration_template

auto print_usage() -> void
{
	fmt::print(R"_(irods_s3_api - Presents an iRODS zone as S3 compatible storage

Usage: irods_s3_api [OPTION]... CONFIG_FILE_PATH

CONFIG_FILE_PATH must point to a file containing a JSON structure containing
configuration options.

--dump-config-template can be used to generate a default configuration file.
See this option's description for more information.

--dump-default-jsonschema can be used to generate a default schema file.
See this option's description for more information.

Options:
      --dump-config-template
                     Print configuration template to stdout and exit. Some
                     options have values which act as placeholders. If used
                     to generate a configuration file, those options will
                     need to be updated.
      --dump-default-jsonschema
                     Print the default JSON schema to stdout and exit. The
                     JSON schema output can be used to create a custom
                     schema. This is for cases where the default schema is
                     too restrictive or contains a bug.
      --jsonschema-file SCHEMA_FILE_PATH
                     Validate server configuration against SCHEMA_FILE_PATH.
                     Validation is performed before startup. If validation
                     fails, the server will exit.
  -h, --help         Display this help message and exit.
  -v, --version      Display version information and exit.

)_");

	print_version_info();
} // print_usage

auto is_valid_configuration(const std::string& _schema_path, const std::string& _config_path) -> bool
{
	try {
		fmt::print("Validating configuration file ...\n");

		namespace jsonschema = jsoncons::jsonschema;

		std::ifstream in{_config_path};
		if (!in) {
			fmt::print(stderr, "Could not open configuration file for validation.\n");
			return false;
		}
		const auto config = jsoncons::json::parse(in);

		jsoncons::json schema;
		if (_schema_path.empty()) {
			fmt::print("No JSON schema file provided. Using default.\n");
			schema = jsoncons::json::parse(default_jsonschema());
		}
		else {
			fmt::print("Using user-provided schema file [{}].\n", _schema_path);
			std::ifstream in{_schema_path};
			if (!in) {
				fmt::print(stderr, "Could not open schema file for validation.\n");
				return false;
			}
			schema = jsoncons::json::parse(in);
		}
		const auto compiled = jsonschema::make_json_schema(std::move(schema));

		jsoncons::json_decoder<jsoncons::ojson> decoder;
		compiled.validate(config, decoder);
		const auto json_result = decoder.get_result();

		if (!json_result.empty()) {
			std::ostringstream out;
			out << pretty_print(json_result);
			fmt::print(stderr, "Configuration failed validation.\n");
			fmt::print(stderr, "{}\n", out.str());
			return false;
		}

		fmt::print("Configuration passed validation!\n");
		return true;
	}
	catch (const std::system_error& e) {
		fmt::print(stderr, "Error: {}\n", e.what());
	}
	catch (const std::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.what());
	}

	return false;
} // is_valid_configuration

auto set_log_level(const json& _config) -> void
{
	const auto iter = _config.find("log_level");

	if (iter == std::end(_config)) {
		spdlog::set_level(spdlog::level::info);
		return;
	}

	const auto& lvl_string = iter->get_ref<const std::string&>();
	auto lvl_enum = spdlog::level::info;

	// clang-format off
	if      (lvl_string == "trace")    { lvl_enum = spdlog::level::trace; }
	else if (lvl_string == "info")     { lvl_enum = spdlog::level::info; }
	else if (lvl_string == "debug")    { lvl_enum = spdlog::level::debug; }
	else if (lvl_string == "warn")     { lvl_enum = spdlog::level::warn; }
	else if (lvl_string == "error")    { lvl_enum = spdlog::level::err; }
	else if (lvl_string == "critical") { lvl_enum = spdlog::level::critical; }
	else                               { logging::warn("Invalid log_level. Setting to [info]."); }
	// clang-format on

	spdlog::set_level(lvl_enum);
} // set_log_level

auto init_tls(const json& _config) -> void
{
	// The iRODS connection libraries do not provide a clean way for developers to easily
	// configure TLS without relying on an irods_environment.json file. All is not lost
	// though. Turns out the iRODS libraries do inspect environment variables. This gives
	// the S3 API a way to hook into the connection logic and support TLS through its
	// own configuration file. Hence, the following environment-based lambda functions.

	const auto set_env_string = [&](const auto& _tls_prop, const char* _env_var, const char* _default_value = "") {
		const auto element_path = fmt::format("/irods_client/tls/{}", _tls_prop);
		const auto v = _config.value(json::json_pointer{element_path}, _default_value);

		if (!v.empty()) {
			const auto env_var_upper = boost::to_upper_copy<std::string>(_env_var);
			logging::trace("Setting environment variable [{}] to [{}].", env_var_upper, v);
			setenv(env_var_upper.c_str(), v.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
		}
	};

	const auto set_env_int = [&_config](const char* _tls_prop, const char* _env_var, int _default_value) {
		const auto element_path = fmt::format("/irods_client/tls/{}", _tls_prop);
		const auto v = _config.value(json::json_pointer{element_path}, _default_value);

		const auto env_var_upper = boost::to_upper_copy<std::string>(_env_var);
		logging::trace("Setting environment variable [{}] to [{}].", env_var_upper, v);
		const auto v_str = std::to_string(v);
		setenv(env_var_upper.c_str(), v_str.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
	};

	// clang-format off
	set_env_string("client_server_policy", irods::KW_CFG_IRODS_CLIENT_SERVER_POLICY, "CS_NEG_REFUSE");
	set_env_string("ca_certificate_file", irods::KW_CFG_IRODS_SSL_CA_CERTIFICATE_FILE);
	set_env_string("verify_server", irods::KW_CFG_IRODS_SSL_VERIFY_SERVER, "cert");
#ifndef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
	set_env_string("client_server_negotiation", irods::KW_CFG_IRODS_CLIENT_SERVER_NEGOTIATION, "request_server_negotiation");
#endif
	set_env_string("encryption_algorithm", irods::KW_CFG_IRODS_ENCRYPTION_ALGORITHM, "AES-256-CBC");

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
	set_env_int("encryption_key_size", irods::KW_CFG_IRODS_ENCRYPTION_KEY_SIZE, 32);

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
	set_env_int("encryption_hash_rounds", irods::KW_CFG_IRODS_ENCRYPTION_NUM_HASH_ROUNDS, 16);

	// NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
	set_env_int("encryption_salt_size", irods::KW_CFG_IRODS_ENCRYPTION_SALT_SIZE, 8);
	// clang-format on
} // init_tls

auto init_irods_connection_pool(const json& _config) -> std::unique_ptr<irods::connection_pool>
{
	const auto& client = _config.at("irods_client");
	const auto& zone = client.at("zone").get_ref<const std::string&>();
	const auto& conn_pool = client.at("connection_pool");
	const auto& rodsadmin = client.at("proxy_admin_account");
	const auto& username = rodsadmin.at("username").get_ref<const std::string&>();

	irods::connection_pool_options opts;

	if (const auto iter = conn_pool.find("refresh_time_in_seconds"); iter != std::end(conn_pool)) {
		opts.number_of_seconds_before_connection_refresh = std::chrono::seconds{iter->get<int>()};
	}

	if (const auto iter = conn_pool.find("max_retrievals_before_refresh"); iter != std::end(conn_pool)) {
		opts.number_of_retrievals_before_connection_refresh = iter->get<std::int16_t>();
	}

	if (const auto iter = conn_pool.find("refresh_when_resource_changes_detected"); iter != std::end(conn_pool)) {
		opts.refresh_connections_when_resource_changes_detected = iter->get<bool>();
	}

	return std::make_unique<irods::connection_pool>(
		conn_pool.at("size").get<int>(),
		client.at("host").get_ref<const std::string&>(),
		client.at("port").get<int>(),
		irods::experimental::fully_qualified_username{username, zone},
		irods::experimental::fully_qualified_username{username, zone},
		[pw = rodsadmin.at("password").get<std::string>()](RcComm& _comm) mutable {
#ifdef IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
			const auto json_input = nlohmann::json{{"scheme", "native"}, {irods::AUTH_PASSWORD_KEY, pw.data()}};
			if (const auto ec = rc_authenticate_client(&_comm, json_input.dump().c_str()); ec != 0)
#else
			if (const auto ec = clientLoginWithPassword(&_comm, pw.data()); ec != 0)
#endif // IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5
			{
				throw std::invalid_argument{fmt::format("Could not authenticate rodsadmin user: [{}]", ec)};
			}
		},
		opts);
} // init_irods_connection_pool

auto init_bucket_mapping(const json& _mapping_config) -> void
{
	const auto& lib_path = _mapping_config.at("plugin_path").get_ref<const std::string&>();
	const auto config_string = _mapping_config.at("configuration").dump();

	logging::trace("{}: Loading shared library at [{}].", __func__, lib_path);
	boost::dll::shared_library lib{lib_path};
	irods::http::globals::set_bucket_mapping_library(lib);

	// clang-format off
	// Make sure the library supports the expected symbols.
	const auto symbols = {
		"bucket_mapping_init",
		"bucket_mapping_list",
		"bucket_mapping_collection",
		"bucket_mapping_close",
		"bucket_mapping_free"
	};
	// clang-format on
	const auto has_symbol = [&lib](const auto& symbol) { return lib.has(symbol); };
	if (!std::all_of(std::begin(symbols), std::end(symbols), has_symbol)) {
		throw std::runtime_error{
			fmt::format("{}: Could not find all required symbols for library [{}].", __func__, lib_path)};
	}

	const auto init_func = lib.get<int(const char*)>("bucket_mapping_init");
	if (const auto ec = init_func(config_string.c_str()); ec != 0) {
		throw std::runtime_error{fmt::format("{}: Plugin initialization failed with code [{}].", __func__, ec)};
	}
} // init_bucket_mapping

auto init_user_mapping(const json& _mapping_config) -> void
{
	const auto& lib_path = _mapping_config.at("plugin_path").get_ref<const std::string&>();
	const auto config_string = _mapping_config.at("configuration").dump();

	logging::trace("{}: Loading shared library at [{}].", __func__, lib_path);
	boost::dll::shared_library lib{lib_path};
	irods::http::globals::set_user_mapping_library(lib);

	// clang-format off
	// Make sure the library supports the expected symbols.
	const auto symbols = {
		"user_mapping_init",
		"user_mapping_irods_username",
		"user_mapping_s3_secret_key",
		"user_mapping_close",
		"user_mapping_free"
	};
	// clang-format on
	const auto has_symbol = [&lib](const auto& symbol) { return lib.has(symbol); };
	if (!std::all_of(std::begin(symbols), std::end(symbols), has_symbol)) {
		throw std::runtime_error{
			fmt::format("{}: Could not find all required symbols for library [{}].", __func__, lib_path)};
	}

	const auto init_func = lib.get<int(const char*)>("user_mapping_init");
	if (const auto ec = init_func(config_string.c_str()); ec != 0) {
		throw std::runtime_error{fmt::format("{}: Plugin initialization failed with code [{}].", __func__, ec)};
	}
} // init_user_mapping

auto main(int _argc, char* _argv[]) -> int
{
	po::options_description opts_desc{""};

	// clang-format off
	opts_desc.add_options()
		("config-file,f", po::value<std::string>(), "")
		("jsonschema-file", po::value<std::string>(), "")
		("dump-config-template", "")
		("dump-default-jsonschema", "")
		("help,h", "")
		("version,v", "");
	// clang-format on

	po::positional_options_description pod;
	pod.add("config-file", 1);

	set_ips_display_name("irods_s3_api");

	try {
		po::variables_map vm;
		po::store(po::command_line_parser(_argc, _argv).options(opts_desc).positional(pod).run(), vm);
		po::notify(vm);

		if (vm.count("help") > 0) {
			print_usage();
			return 0;
		}

		if (vm.count("version") > 0) {
			print_version_info();
			return 0;
		}

		if (vm.count("dump-config-template") > 0) {
			print_configuration_template();
			return 0;
		}

		if (vm.count("dump-default-jsonschema") > 0) {
			fmt::print("{}\n", default_jsonschema());
			return 0;
		}

		if (vm.count("config-file") == 0) {
			fmt::print(stderr, "Error: Missing [CONFIG_FILE_PATH] parameter.");
			return 1;
		}

		const auto& config_file_path = vm["config-file"].as<std::string>();
		if (!fs::exists(config_file_path)) {
			fmt::print(stderr, "Error: Configuration file [{}] does not exist.\n", config_file_path);
			return 1;
		}

		const auto config = [&config_file_path] {
			std::ifstream file{config_file_path};
			if (!file.is_open()) {
				throw std::runtime_error{fmt::format("Cannot open configuration file [{}].", config_file_path)};
			}

			return json::parse(file);
		}();

		irods::http::globals::set_configuration(config);

		{
			const auto schema_file = (vm.count("jsonschema-file") > 0) ? vm["jsonschema-file"].as<std::string>() : "";
			if (!is_valid_configuration(schema_file, vm["config-file"].as<std::string>())) {
				return 1;
			}
		}

		const auto& s3_server_config = config.at("s3_server");
		set_log_level(s3_server_config);

		spdlog::set_pattern("[%Y-%m-%d %T.%e] [P:%P] [%^%l%$] [T:%t] %v");

		logging::info("Initializing server.");

		// TODO For LONG running tasks, see the following:
		//
		//   - https://stackoverflow.com/questions/17648725/long-running-blocking-operations-in-boost-asio-handlers
		//   - https://www.open-std.org/JTC1/SC22/WG21/docs/papers/2012/n3388.pdf
		//

		logging::trace("Loading API plugins.");
		load_client_api_plugins();

		init_bucket_mapping(s3_server_config.at(json::json_pointer{"/bucket_mapping"}));
		init_user_mapping(s3_server_config.at(json::json_pointer{"/user_mapping"}));

		const auto address = net::ip::make_address(s3_server_config.at("host").get_ref<const std::string&>());
		const auto port = s3_server_config.at("port").get<std::uint16_t>();
		const auto request_thread_count =
			std::max(s3_server_config.at(json::json_pointer{"/requests/threads"}).get<int>(), 1);

		logging::trace("Initializing TLS.");
		init_tls(config);

		// Ignore SIGPIPE. The iRODS networking code assumes SIGPIPE is ignored so that broken
		// socket connections can be detected at the call site. This MUST be called before any
		// iRODS connections are established.
		std::signal(SIGPIPE, SIG_IGN); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)

		std::unique_ptr<irods::connection_pool> conn_pool;

		if (!config.at(json::json_pointer{"/irods_client/enable_4_2_compatibility"}).get<bool>()) {
			logging::trace("Initializing iRODS connection pool.");
			conn_pool = init_irods_connection_pool(config);
			irods::http::globals::set_connection_pool(*conn_pool);
		}

		// The io_context is required for all I/O.
		logging::trace("Initializing HTTP components.");
		net::io_context ioc{request_thread_count};
		irods::http::globals::set_request_handler_io_context(ioc);

		// Create and launch a listening port.
		logging::trace("Initializing listening socket (host=[{}], port=[{}]).", address.to_string(), port);
		std::make_shared<listener>(ioc, tcp::endpoint{address, port}, config)->run();

		// SIGINT and SIGTERM instruct the server to shut down.
		logging::trace("Initializing signal handlers.");

		net::signal_set signals{ioc, SIGINT, SIGTERM};

		signals.async_wait([&ioc](const beast::error_code&, int _signal) {
			// Stop the io_context. This will cause run() to return immediately, eventually destroying
			// the io_context and all of the sockets in it.
			logging::warn("Received signal [{}]. Shutting down.", _signal);
			ioc.stop();
		});

		// Launch the requested number of dedicated backgroup I/O threads.
		// These threads are used for long running tasks (e.g. reading/writing bytes, database, etc.)
		logging::trace("Initializing thread pool for long running I/O tasks.");
		net::thread_pool io_threads(
			std::max(s3_server_config.at(json::json_pointer{"/background_io/threads"}).get<int>(), 1));
		irods::http::globals::set_background_thread_pool(io_threads);

		// Run the I/O service on the requested number of threads.
		logging::trace("Initializing thread pool for HTTP requests.");
		net::thread_pool request_handler_threads(request_thread_count);
		for (auto i = request_thread_count - 1; i > 0; --i) {
			net::post(request_handler_threads, [&ioc] {
				try {
					ioc.run();
				}
				catch (const std::exception& e) {
					logging::error("main: Lost io_context thread due to exception: {}", e.what());
				}
			});
		}

		logging::info("Server is ready.");
		ioc.run();

		request_handler_threads.stop();
		io_threads.stop();

		logging::trace("Waiting for HTTP requests thread pool to shut down.");
		request_handler_threads.join();

		logging::trace("Waiting for I/O thread pool to shut down.");
		io_threads.join();

		logging::trace("Releasing resources for user mapping plugin.");
		bool plugin_close_error = false;
		auto um_close = irods::http::globals::user_mapping_library().get<int()>("user_mapping_close");
		if (const auto ec = um_close(); ec != 0) {
			logging::error("User mapping plugin experienced an error during shut down. [error_code={}].", ec);
			plugin_close_error = true;
		}

		logging::trace("Releasing resources for bucket mapping plugin.");
		auto bm_close = irods::http::globals::bucket_mapping_library().get<int()>("bucket_mapping_close");
		if (const auto ec = bm_close(); ec != 0) {
			logging::error("Bucket mapping plugin experienced an error during shut down. [error_code={}].", ec);
			plugin_close_error = true;
		}

		logging::info("Shutdown complete.");

		return plugin_close_error ? 1 : 0;
	}
	catch (const irods::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.client_display_what());
	}
	catch (const std::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.what());
	}

	return 1;
} // main
