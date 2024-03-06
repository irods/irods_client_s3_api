#ifndef IRODS_S3_API_BUCKET_HPP
#define IRODS_S3_API_BUCKET_HPP

#include "boost/url.hpp"
#include <irods/filesystem.hpp>

namespace irods::s3
{
	/// Get the base path of the given bucket in the request.
	///
	/// \param connection The connection to the irods server.
	/// \param view The view of the url's segments.
	std::optional<irods::experimental::filesystem::path> resolve_bucket(const boost::urls::segments_view& view);

	/// Get the final path of the given bucket in the request.
	///
	/// \param base The base irods path for the bucket
	/// \param view The view of the url's segments.
	irods::experimental::filesystem::path finish_path(
		const irods::experimental::filesystem::path& base,
		const boost::urls::segments_view&);
	std::string strip_bucket(const std::string&);
} //namespace irods::s3
#endif // IRODS_S3_API_BUCKET_HPP
