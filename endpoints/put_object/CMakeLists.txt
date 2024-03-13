add_library(
  irods_s3_api_endpoint_put_object
  OBJECT
  "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp"
)

target_compile_definitions(
  irods_s3_api_endpoint_put_object
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

target_link_libraries(
  irods_s3_api_endpoint_put_object
  PRIVATE
  irods_client
  CURL::libcurl
  nlohmann_json::nlohmann_json
)

target_include_directories(
  irods_s3_api_endpoint_put_object
  PRIVATE
  "${IRODS_S3_API_PROJECT_SOURCE_DIR}/core/include"
  "${IRODS_S3_API_PROJECT_BINARY_DIR}/core/include"
  "${IRODS_S3_API_PROJECT_SOURCE_DIR}/endpoints/shared/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
)

if (IRODS_VERSION VERSION_GREATER "4.3.1")
  target_link_libraries(
    irods_s3_api_endpoint_put_object
    PUBLIC
    fmt::fmt
    spdlog::spdlog
  )
else()
  target_link_libraries(
    irods_s3_api_endpoint_put_object
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  )

  target_include_directories(
    irods_s3_api_endpoint_put_object
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
    "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
  )
endif()

set_target_properties(irods_s3_api_endpoint_put_object PROPERTIES EXCLUDE_FROM_ALL TRUE)
