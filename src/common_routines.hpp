#ifndef IRODS_S3_API_COMMON_ROUTINES_HPP
#define IRODS_S3_API_COMMON_ROUTINES_HPP

#include <fmt/format.h>
#include <fmt/chrono.h>

namespace irods::s3::api::common_routines {

    inline std::string convert_time_t_to_str(const time_t& t, const std::string_view format) {
        return fmt::format(fmt::runtime(format), fmt::localtime(t));
    }
}

#endif // IRODS_S3_API_COMMON_ROUTINES_HPP
