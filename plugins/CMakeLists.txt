include(GNUInstallDirs)

set(
  IRODS_S3_API_PLUGINS_DIRECTORY
  "${CMAKE_INSTALL_LIBDIR}/irods_s3_api/plugins"
)

add_subdirectory(bucket_mapping)
add_subdirectory(user_mapping)
