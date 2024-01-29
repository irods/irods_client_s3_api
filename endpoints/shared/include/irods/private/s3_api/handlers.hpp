#ifndef IRODS_S3_API_HANDLERS_HPP
#define IRODS_S3_API_HANDLERS_HPP

#include "irods/private/s3_api/common.hpp"

#ifndef IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE
// Enables all endpoint function signatures for declarations and definitions to be
// updated from one location.
#  define IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(name) \
	auto name(session_pointer_type _sess_ptr, request_type& _req)->void
#endif // IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE

namespace irods::http::handler
{
	IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(authentication);

	IRODS_S3_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(put_object);
} // namespace irods::http::handler

#endif // IRODS_S3_API_HANDLERS_HPP
