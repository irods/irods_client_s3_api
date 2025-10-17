set(IRODS_BUILD_CATCH2_TESTS NO CACHE BOOL "Build Catch2 unit tests")

if (NOT IRODS_BUILD_CATCH2_TESTS)
  return()
endif()

find_package(Catch2 3.4)
if (NOT Catch2_FOUND)
  find_package(Catch2 2.13.2 REQUIRED)
endif()

include(Catch)

# Enable CTest.
enable_testing()

set(IRODS_TEST_EXECUTABLE irods_s3_api-unit_tests)

add_executable(
  ${IRODS_TEST_EXECUTABLE}
  main.cpp
  plugins.cpp
)

add_dependencies(
  ${IRODS_TEST_EXECUTABLE}
  irods_s3_api_plugin-bucket_mapping-local_file
  irods_s3_api_plugin-user_mapping-local_file
)

target_include_directories(
  ${IRODS_TEST_EXECUTABLE}
  PRIVATE
  "${CMAKE_SOURCE_DIR}/plugins/bucket_mapping/include"
  "${CMAKE_SOURCE_DIR}/plugins/user_mapping/include"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
)

target_link_libraries(
  ${IRODS_TEST_EXECUTABLE}
  PRIVATE
  Catch2::Catch2
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
)

if (IRODS_VERSION VERSION_GREATER "4.3.1")
  target_link_libraries(
    ${IRODS_TEST_EXECUTABLE}
    PUBLIC
    fmt::fmt
    spdlog::spdlog
  )
else()
  target_link_libraries(
    ${IRODS_TEST_EXECUTABLE}
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
  )

  target_include_directories(
    ${IRODS_TEST_EXECUTABLE}
    PRIVATE
    "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
    "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
  )
endif()

# Make the test available to CTest.
catch_discover_tests(${IRODS_TEST_EXECUTABLE})
