#include "irods/private/s3_api/hmac.hpp"
#include "hmac_sha256.h"
#include "irods/private/s3_api/log.hpp"

extern "C" {
#include "sha256.h"
}

#include <fmt/core.h>
#include <sstream>
#include <iostream>

namespace irods::s3::authentication
{
    std::string hmac_sha_256(const std::string_view& key, const std::string_view& data)
    {
        namespace log = irods::http::log;
        unsigned char result[32];
        unsigned int result_size = 32;
        hmac_sha256(key.data(), key.length(), data.data(), data.length(), result, 32);
        log::trace("HMAC size is {} bytes", result_size);
        return std::string(std::string_view((char*) result, 32));
    }

    std::string hash_sha_256(const std::string_view& data)
    {
        Sha256Context ctx;
        Sha256Initialise(&ctx);
        Sha256Update(&ctx, static_cast<const void*>(data.data()), data.length());
        SHA256_HASH hash;
        Sha256Finalise(&ctx, &hash);
        return std::string((char*) hash.bytes, 32);
    }

    std::string hex_encode(const std::string_view& data)
    {
        std::stringstream s;
        for (size_t i = 0; i < data.length(); i++) {
            s << fmt::format("{:02x}", (unsigned char) data[i]);
        }
        return s.str();
    }
} //namespace irods::s3::authentication
