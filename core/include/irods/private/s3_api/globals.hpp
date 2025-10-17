#ifndef IRODS_S3_API_GLOBALS_HPP
#define IRODS_S3_API_GLOBALS_HPP

#include <irods/connection_pool.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/dll.hpp>

#include <nlohmann/json.hpp>

#include <functional>

// TODO(#180): Rename namespace: http -> s3
namespace irods::http::globals
{
	auto set_configuration(const nlohmann::json& _config) -> void;
	auto configuration() -> const nlohmann::json&;

	auto set_request_handler_io_context(boost::asio::io_context& _ioc) -> void;
	auto request_handler_io_context() -> boost::asio::io_context&;

	auto set_background_thread_pool(boost::asio::thread_pool& _tp) -> void;
	auto background_thread_pool() -> boost::asio::thread_pool&;
	auto background_task(std::function<void()> _task) -> void;

	auto set_connection_pool(irods::connection_pool& _cp) -> void;
	auto connection_pool() -> irods::connection_pool&;

	auto set_bucket_mapping_library(boost::dll::shared_library _lib) -> void;
	auto bucket_mapping_library() -> boost::dll::shared_library&;

	auto set_user_mapping_library(boost::dll::shared_library _lib) -> void;
	auto user_mapping_library() -> boost::dll::shared_library&;
} // namespace irods::http::globals

#endif // IRODS_S3_API_GLOBALS_HPP
