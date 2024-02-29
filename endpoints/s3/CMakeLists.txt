add_library(
  irods_s3_endpoints
  OBJECT
  "${CMAKE_CURRENT_SOURCE_DIR}/src/listobjects.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/listbuckets.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/getobject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/putobject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/deleteobject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/deleteobjects.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/headobject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/headbucket.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/copyobject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/createmultipartupload.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/completemultipartupload.cpp"
)

target_compile_definitions(
  irods_s3_endpoints
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS}
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

target_link_libraries(
  irods_s3_endpoints
  PRIVATE
  irods_client
  CURL::libcurl
  nlohmann_json::nlohmann_json
)

target_include_directories(
  irods_s3_endpoints
  PRIVATE
  "${IRODS_S3_API_PROJECT_SOURCE_DIR}/core/include"
  "${IRODS_S3_API_PROJECT_BINARY_DIR}/core/include"
  "${IRODS_S3_API_PROJECT_SOURCE_DIR}/endpoints/shared/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
  "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
)

set_target_properties(irods_s3_endpoints PROPERTIES EXCLUDE_FROM_ALL TRUE)
