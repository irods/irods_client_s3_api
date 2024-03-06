#ifndef IRODS_S3_API_HMAC_HPP
#define IRODS_S3_API_HMAC_HPP
#include <string_view>
#include <string>
#include <vector>

namespace irods::s3::authentication
{
	/// Produce a hmac_sha_256 signature
	/// @param key The key
	/// @param data The data
	/// @returns the signature
	std::string hmac_sha_256(const std::string_view& key, const std::string_view& data);

	/// Produce a sha256 hash
	/// @param data The range of bytes to hash.
	/// @returns The hash
	std::string hash_sha_256(const std::string_view& data);

	/// Encode a string view in hexadecimal.
	/// @param data the data to convert to string
	std::string hex_encode(const std::string_view& data);
} //namespace irods::s3::authentication
#endif // IRODS_S3_API_HMAC_HPP