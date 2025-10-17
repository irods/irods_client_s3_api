set(plugin "local_file")
set(plugin_target "irods_s3_api_plugin-bucket_mapping-${plugin}")
set(plugin_name "irods_s3_api_plugin-bucket_mapping-${plugin}")

add_library(
  ${plugin_target}
  MODULE
  "${CMAKE_CURRENT_SOURCE_DIR}/src/${plugin}.cpp"
)
set_property(TARGET ${plugin_target} PROPERTY LIBRARY_OUTPUT_NAME ${plugin_name})

target_link_libraries(
  ${plugin_target}
  PRIVATE
  irods_common
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  ${CMAKE_DL_LIBS}
)

if (IRODS_VERSION VERSION_GREATER "4.3.1")
  target_link_libraries(
    ${plugin_target}
    PRIVATE
    fmt::fmt
    spdlog::spdlog
  )
else()
  target_link_libraries(
    ${plugin_target}
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  )
  target_include_directories(
    ${plugin_target}
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
    "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
  )
endif()

target_include_directories(
  ${plugin_target}
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
  "${IRODS_EXTERNALS_FULLPATH_JSONCONS}/include"
)

target_compile_definitions(
  ${plugin_target}
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)

install(
  TARGETS
  ${plugin_target}
  LIBRARY
  DESTINATION "${IRODS_S3_API_PLUGINS_DIRECTORY}/bucket_mapping"
)
