#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/handlers.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/transport.hpp"
#include "irods/private/s3_api/process_stash.hpp"
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

#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
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
namespace logging = irods::http::logging;

using json = nlohmann::json;
using tcp  = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

// IRODS_S3_API_BASE_URL is a macro defined by the CMakeLists.txt.
const irods::http::request_handler_map_type req_handlers{
	{IRODS_S3_API_BASE_URL "/authenticate", irods::http::handler::authentication},
	{IRODS_S3_API_BASE_URL "/PutObject",  irods::http::handler::put_object}
};
// clang-format on

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
			std::make_shared<irods::http::session>(std::move(socket), req_handlers, max_body_size_, timeout_in_secs_)
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
                "plugins": {
                    "type": "object"
                },
                "region": {
                    "type": "string"
                },
                "multipart_upload_part_files_directory": {
                    "type": "string"
                },
                "authentication": {
                    "type": "object",
                    "properties": {
                        "eviction_check_interval_in_seconds": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "basic": {
                            "type": "object",
                            "properties": {
                                "timeout_in_seconds": {
                                    "type": "integer",
                                    "minimum": 1
                                }
                            },
                            "required": [
                                "timeout_in_seconds"
                            ]
                        }
                    },
                    "required": [
                        "eviction_check_interval_in_seconds",
                        "basic"
                    ]
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
                "authentication",
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
                        }
                    },
                    "required": [
                        "client_server_policy",
                        "ca_certificate_file",
                        "dh_params_file",
                        "verify_server"
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

        "plugins": {{
            "static_bucket_resolver": {{
                "name": "static_bucket_resolver",
                "mappings": {{
                    "<bucket_name>": "/path/to/collection"
                }}
            }},

            "static_authentication_resolver": {{
                "name": "static_authentication_resolver",
                "users": {{
                    "<s3_username>": {{
                        "username": "<string>",
                        "secret_key": "<string>"
                    }}
                }}
            }}
        }},

        "region": "us-east-1",

        "multipart_upload_part_files_directory": "/tmp",

        "authentication": {{
            "eviction_check_interval_in_seconds": 60,

            "basic": {{
                "timeout_in_seconds": 3600
            }}
        }},

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
            "verify_server": "<string>"
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
	const auto set_env_var = [&](const auto& _json_ptr_path, const char* _env_var, const char* _default_value = "") {
		using json_ptr = json::json_pointer;

		if (const auto v = _config.value(json_ptr{_json_ptr_path}, _default_value); !v.empty()) {
			const auto env_var_upper = boost::to_upper_copy<std::string>(_env_var);
			logging::trace("Setting environment variable [{}] to [{}].", env_var_upper, v);
			setenv(env_var_upper.c_str(), v.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
		}
	};

	set_env_var("/irods_client/tls/client_server_policy", irods::KW_CFG_IRODS_CLIENT_SERVER_POLICY, "CS_NEG_REFUSE");
	set_env_var("/irods_client/tls/ca_certificate_file", irods::KW_CFG_IRODS_SSL_CA_CERTIFICATE_FILE);
	set_env_var("/irods_client/tls/certificate_chain_file", irods::KW_CFG_IRODS_SSL_CERTIFICATE_CHAIN_FILE);
	set_env_var("/irods_client/tls/dh_params_file", irods::KW_CFG_IRODS_SSL_DH_PARAMS_FILE);
	set_env_var("/irods_client/tls/verify_server", irods::KW_CFG_IRODS_SSL_VERIFY_SERVER, "cert");
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

class process_stash_eviction_manager
{
	net::steady_timer timer_;
	std::chrono::seconds interval_;

  public:
	process_stash_eviction_manager(net::io_context& _io, std::chrono::seconds _eviction_check_interval)
		: timer_{_io}
		, interval_{_eviction_check_interval}
	{
		evict();
	} // constructor

  private:
	auto evict() -> void
	{
		timer_.expires_after(interval_);
		timer_.async_wait([this](const auto& _ec) {
			if (_ec) {
				return;
			}

			logging::trace("Evicting expired items ...");
			irods::http::process_stash::erase_if([](const auto& _k, const auto& _v) {
				const auto* client_info = boost::any_cast<const irods::http::authenticated_client_info>(&_v);
				const auto erase_value = client_info && std::chrono::steady_clock::now() >= client_info->expires_at;

				if (erase_value) {
					logging::debug("Evicted bearer token [{}].", _k);
				}

				return erase_value;
			});

			evict();
		});
	} // evict
}; // class process_stash_eviction_manager

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

		const auto config = json::parse(std::ifstream{vm["config-file"].as<std::string>()});
		irods::http::globals::set_configuration(config);

#if 0
		{
			const auto schema_file = (vm.count("jsonschema-file") > 0) ? vm["jsonschema-file"].as<std::string>() : "";
			if (!is_valid_configuration(schema_file, vm["config-file"].as<std::string>())) {
				return 1;
			}
		}
#endif

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

		// Launch eviction check for expired bearer tokens.
		const auto eviction_check_interval =
			s3_server_config.at(json::json_pointer{"/authentication/eviction_check_interval_in_seconds"}).get<int>();
		process_stash_eviction_manager eviction_mgr{ioc, std::chrono::seconds{eviction_check_interval}};

		logging::info("Server is ready.");
		ioc.run();

		request_handler_threads.stop();
		io_threads.stop();

		logging::trace("Waiting for HTTP requests thread pool to shut down.");
		request_handler_threads.join();

		logging::trace("Waiting for I/O thread pool to shut down.");
		io_threads.join();

		logging::info("Shutdown complete.");

		return 0;
	}
	catch (const irods::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.client_display_what());
	}
	catch (const std::exception& e) {
		fmt::print(stderr, "Error: {}\n", e.what());
	}

	return 1;
} // main
