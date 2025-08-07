cmake_minimum_required(VERSION 3.18.0 FATAL_ERROR)

#
# Build Configuration
#

find_package(IRODS REQUIRED)

include(RequireOutOfSourceBuild)

set(IRODS_S3_API_BINARY_NAME "irods_s3_api")

set(IRODS_CLIENT_VERSION "0.3.0")
set(IRODS_S3_API_VERSION "${IRODS_CLIENT_VERSION}")

set(IRODS_PACKAGE_REVISION "0")

include(IrodsExternals)

include(IrodsCXXCompiler)
set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_CXX_EXTENSIONS OFF)
# export-dynamic so stacktrace entries from executables have function names.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--export-dynamic -Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
include(IrodsRunpathDefaults)

project(${IRODS_S3_API_BINARY_NAME} VERSION "${IRODS_S3_API_VERSION}" LANGUAGES CXX)

find_package(Threads REQUIRED)

include("${IRODS_TARGETS_PATH}")
include(GNUInstallDirs)

if (IRODS_VERSION VERSION_LESS 4.90.0)
  include(UseLibCXX)
endif()

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
  message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'. This is the correct setting for normal builds.")
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
  set(IRODS_BUILD_WITH_WERROR_DEFAULT ON)
else()
  set(IRODS_BUILD_WITH_WERROR_DEFAULT OFF)
endif()
set(IRODS_BUILD_WITH_WERROR ${IRODS_BUILD_WITH_WERROR_DEFAULT} CACHE BOOL "Choose whether to compile with -Werror.")

if (IRODS_BUILD_WITH_WERROR)
  add_compile_options(-Werror)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

if (IRODS_VERSION VERSION_GREATER_EQUAL 4.90.0)
  # TODO(irods/irods#8580): Remove once library_features.h provides macros to detect the new functions.
  # iRODS 5 deprecates the clientLogin-family of functions and introduces new support functions for
  # authentication. This macro signals that the new functions are available.
  add_compile_definitions(IRODS_DEV_PACKAGE_IS_AT_LEAST_IRODS_5)
endif()

option(IRODS_ENABLE_ADDRESS_SANITIZER "Enables detection of memory leaks and other features provided by Address Sanitizer." OFF)
if (IRODS_ENABLE_ADDRESS_SANITIZER)
  # Make sure the correct llvm-symbolizer binary is available to Address Sanitizer. This binary
  # allows debug symbols to be reported appropriately. There are two ways to do this:
  #
  #     export PATH=/opt/irods-externals/clang13.0.0-0/bin:$PATH
  #
  # - or -
  #
  #     export ASAN_SYMBOLIZER_PATH=/opt/irods-externals/clang13.0.0-0/bin/llvm-symbolizer
  #
  # detect_container_overflow is disabled to guard against false positives which occur when
  # parts of the binary are compiled with ASAN and other parts are not.
  add_compile_definitions(IRODS_ADDRESS_SANITIZER_DEFAULT_OPTIONS="log_path=/tmp/irods_client_s3_api_asan_output:detect_container_overflow=0")
  add_compile_options(
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -O1)
  add_link_options(
    -fsanitize=address
    -fno-omit-frame-pointer
    -fno-optimize-sibling-calls
    -O1)
else()
  set(CMAKE_EXE_LINKER_FLAGS_INIT "${CMAKE_EXE_LINKER_FLAGS_INIT} -Wl,-z,defs")
endif()

set(IRODS_S3_API_PROJECT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(IRODS_S3_API_PROJECT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

find_package(CURL REQUIRED)
find_package(nlohmann_json "3.6.1" REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

if (IRODS_VERSION VERSION_GREATER "4.3.1")
  find_package(fmt "8.1.1"
    HINTS "${IRODS_EXTERNALS_FULLPATH_FMT}")
  find_package(spdlog "1.9.2"
    HINTS "${IRODS_EXTERNALS_FULLPATH_SPDLOG}")
endif()

include(ObjectTargetHelpers)

add_subdirectory(core)
add_subdirectory(endpoints)
add_subdirectory(third-party/hmac_sha256)

add_executable(${IRODS_S3_API_BINARY_NAME})
target_link_objects(
  ${IRODS_S3_API_BINARY_NAME}
  PRIVATE
  irods_s3_api_core
  irods_s3_api_endpoint_authentication
  irods_s3_api_endpoint_put_object
  irods_s3_endpoints
)

install(
    TARGETS
    ${IRODS_S3_API_BINARY_NAME}
    DESTINATION "${CMAKE_INSTALL_BINDIR}")

#
# Packaging Configuration
#

include(IrodsCPackCommon)
include(IrodsCPackPlatform)

set(IRODS_PACKAGE_NAME irods-client-s3-api)

#list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
#list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
#list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
#list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

set(CPACK_PACKAGE_VERSION ${IRODS_CLIENT_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
#set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")
#set(CPACK_DEBIAN_PACKAGE_BREAKS ${IRODS_S3_API_BINARY_NAME})
#set(CPACK_DEBIAN_PACKAGE_REPLACES ${IRODS_S3_API_BINARY_NAME})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
#set(CPACK_RPM_PACKAGE_OBSOLETES ${IRODS_S3_API_BINARY_NAME})
#set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME ${IRODS_PACKAGE_NAME})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "irods-runtime (= ${IRODS_VERSION})")

get_filename_component(CURL_LIBRARY_REALPATH ${CURL_LIBRARY} REALPATH)
get_filename_component(CURL_LIBRARY_REALNAME ${CURL_LIBRARY_REALPATH} NAME_WE)
if (CURL_LIBRARY_REALNAME STREQUAL "libcurl-gnutls")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl3-gnutls")
elseif (CURL_LIBRARY_REALNAME STREQUAL "libcurl-nss")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl3-nss")
elseif (CURL_LIBRARY_REALNAME STREQUAL "libcurl")
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl4")
endif ()

set(CPACK_RPM_PACKAGE_NAME ${IRODS_PACKAGE_NAME})
set(CPACK_RPM_PACKAGE_REQUIRES "irods-runtime = ${IRODS_VERSION}, libcurl")

if (NOT CPACK_GENERATOR)
  set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
  message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)
