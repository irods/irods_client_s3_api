target_sources(
  irods_s3_api
  PRIVATE
  main.cpp
  connection.cpp
  configuration.cpp
  persistence_plugin.cpp
  hmac.cpp
  authentication.cpp bucket_plugin.cpp
  multipart.cpp
  auth_plugin.cpp
  plugin.cpp)

add_subdirectory(plugins)
add_subdirectory(s3)
