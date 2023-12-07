cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

set(IRODS_CLIENT_VERSION "0.1.0")
set(IRODS_PACKAGE_REVISION "0")

#
# Build Configuration
#

find_package(IRODS 4.3.1 REQUIRED)

include(RequireOutOfSourceBuild)
include(IrodsCXXCompiler)

set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_CXX_EXTENSIONS OFF)
# export-dynamic so stacktrace entries from executables have function names.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-rdynamic -Wl,--export-dynamic -Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
# we have intentionally(?) undefined symbols in the plugins, so no -Wl,-z,defs
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
include(IrodsRunpathDefaults)

project(irods_client_s3_api VERSION "${IRODS_CLIENT_VERSION}" LANGUAGES CXX C)

include(${IRODS_TARGETS_PATH})
include(GNUInstallDirs)
include(UseLibCXX)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

add_subdirectory(third-party/hmac_sha256)

include_directories(
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include
  ${IRODS_EXTERNALS_FULLPATH_FMT}/include)

find_package(CURL REQUIRED)
find_package(nlohmann_json "3.6.1" REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Threads REQUIRED)

set(IRODS_S3_API_BINARY_NAME irods_s3_api)
add_executable(${IRODS_S3_API_BINARY_NAME})

set(IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME static_bucket_resolver)
add_library(${IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME} MODULE)

set(IRODS_S3_API_AUTH_RESOLVER_NAME static_authentication_resolver)
add_library(${IRODS_S3_API_AUTH_RESOLVER_NAME} MODULE)

set(IRODS_S3_API_PERSISTENCE_PLUGIN sqlite_persistence_plugin)
add_library(${IRODS_S3_API_PERSISTENCE_PLUGIN} MODULE)

target_link_libraries(
  ${IRODS_S3_API_BINARY_NAME}
  PRIVATE 
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so
  irods_client
  hmac_sha256
  ${CMAKE_DL_LIBS} 
  CURL::libcurl
  nlohmann_json::nlohmann_json
  Threads::Threads)

target_include_directories(${IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME} PRIVATE src)
target_include_directories(${IRODS_S3_API_AUTH_RESOLVER_NAME} PRIVATE src)
target_include_directories(${IRODS_S3_API_PERSISTENCE_PLUGIN} PRIVATE src)

target_link_libraries(
  ${IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME}
  PRIVATE
  irods_client
  ${CMAKE_DL_LIBS}
  CURL::libcurl
  nlohmann_json::nlohmann_json
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so)

target_link_libraries(
  ${IRODS_S3_API_AUTH_RESOLVER_NAME}
  PRIVATE
  irods_client
  ${CMAKE_DL_LIBS}
  CURL::libcurl
  nlohmann_json::nlohmann_json
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so)

target_link_libraries(
  ${IRODS_S3_API_PERSISTENCE_PLUGIN}
  PRIVATE
  irods_client
  ${CMAKE_DL_LIBS}
  CURL::libcurl
  nlohmann_json::nlohmann_json
  ${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so)

target_include_directories(
  ${IRODS_S3_API_BINARY_NAME}
  PRIVATE
  third-party/hmac_sha256
  ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)

target_include_directories(${IRODS_S3_API_AUTH_RESOLVER_NAME} PRIVATE ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)
target_include_directories(${IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME} PRIVATE ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)
target_include_directories(${IRODS_S3_API_PERSISTENCE_PLUGIN} PRIVATE ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)

add_subdirectory(src)

install(
  TARGETS
  ${IRODS_S3_API_BINARY_NAME}
  ${IRODS_S3_API_AUTH_RESOLVER_NAME}
  ${IRODS_S3_API_BUCKET_RESOLVER_PLUGIN_NAME}
  DESTINATION "${LIBDIR}/irods/clients/s3_api")

#
# Packaging Configuration
#

include(IrodsCPackCommon)
include(IrodsCPackPlatform)

set(IRODS_PACKAGE_NAME irods-experimental-client-s3-api)

set(CPACK_PACKAGE_VERSION ${IRODS_CLIENT_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_PACKAGE_RELEASE "${IRODS_PACKAGE_REVISION}")
if (IRODS_LINUX_DISTRIBUTION_VERSION_CODENAME)
  set(CPACK_DEBIAN_PACKAGE_RELEASE "${CPACK_DEBIAN_PACKAGE_RELEASE}~${IRODS_LINUX_DISTRIBUTION_VERSION_CODENAME}")
endif()
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
#set(CPACK_RPM_PACKAGE_OBSOLETES ${IRODS_PACKAGE_NAME})
#set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_PACKAGE_RELEASE "${IRODS_PACKAGE_REVISION}")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${CMAKE_INSTALL_LIBEXECDIR}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${CMAKE_INSTALL_LIBEXECDIR}/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${CMAKE_INSTALL_LIBEXECDIR}/irods/clients")

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME "${IRODS_PACKAGE_NAME}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime (= ${IRODS_VERSION})")

set(CPACK_RPM_PACKAGE_NAME "${IRODS_PACKAGE_NAME}")
set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}")

if (NOT CPACK_GENERATOR)
  set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
  message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)
