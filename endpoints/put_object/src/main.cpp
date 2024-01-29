#include "irods/private/s3_api/handlers.hpp"

#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/globals.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/version.hpp"

#include <irods/collCreate.h>
#include <irods/dataObjInpOut.h>
#include <irods/filesystem.hpp>
#include <irods/filesystem/path_utilities.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/system_error.hpp> // For make_error_code
#include <irods/touch.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace fs      = irods::experimental::filesystem;
namespace logging = irods::http::logging;
// clang-format on

#define IRODS_S3_API_ENDPOINT_OPERATION_SIGNATURE(name) \
  auto name(                                            \
	  irods::http::session_pointer_type _sess_ptr,      \
	  irods::http::request_type& _req,                  \
	  irods::http::query_arguments_type& _args)         \
	  ->void

namespace
{
	//
	// Handler function prototypes
	//

	IRODS_S3_API_ENDPOINT_OPERATION_SIGNATURE(op_test);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_get{
		{"test_get", op_test}
	};

	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_post{
		{"test_put", op_test}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(put_object)
	{
		execute_operation(_sess_ptr, _req, handlers_for_get, handlers_for_post);
	} // put_object
} // namespace irods::http::handler

namespace
{
	//
	// Operation handler implementations
	//

	IRODS_S3_API_ENDPOINT_OPERATION_SIGNATURE(op_test)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::s3::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				res.body() = "THIS IS A TEST!";
				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_test
} // anonymous namespace
