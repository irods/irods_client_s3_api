# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project **only** adheres to the following _(as defined at [Semantic Versioning](https://semver.org/spec/v2.0.0.html))_:

> Given a version number MAJOR.MINOR.PATCH, increment the:
> 
> - MAJOR version when you make incompatible API changes
> - MINOR version when you add functionality in a backward compatible manner
> - PATCH version when you make backward compatible bug fixes

## [0.5.0] - 2025-11-03

> [!IMPORTANT]
> This version requires modification of the S3 API server's configuration file.

This release separates bucket mapping and user mapping from the main configuration file through use of a new plugin architecture. Administrators can now adjust mappings in real time without needing to restart the S3 API server.

See the following README sections to learn more about the configuration and plugins.
- [Configuration File Structure](https://github.com/irods/irods_client_s3_api/tree/0.5.0#configuration-file-structure)
- [Bucket Mapping](https://github.com/irods/irods_client_s3_api/tree/0.5.0#bucket-mapping)
- [User Mapping](https://github.com/irods/irods_client_s3_api/tree/0.5.0#user-mapping)
- [Custom Plugins](https://github.com/irods/irods_client_s3_api/tree/0.5.0#custom-plugins)

### Changed

- Move management of bucket and user mapping to plugin architecture (#118).

### Removed

- Remove unnecessary TLS configuration properties from configuration file (#182).

### Fixed

- Add missing TLS configuration properties to configuration file (#169).

## [0.4.0] - 2025-08-20

This release makes the S3 API compatible with iRODS 5 and adds support for Presigned URLs.

The server also performs validation of the configuration file on startup.

### Changed

- Update default JSON schema and template configuration strings (#62).
- Remove version from JSON schema `$id` property (#128).
- Use jsoncons C++ library for configuration validation (#146).
- Do not use apt-key for package repositories (irods/irods#6008).
- Migrate to system CMake (irods/irods#8330).

### Fixed

- Fix comparison to guarantee multipart global state is cleaned up (#130).
- Fix lack of `return` keyword in `set_log_level()` (#138).
- Fix CopyObject operation using empty resource name on overwrite (#160).

### Added

- Make server validate configuration on startup (#62).
- Implement support for Presigned URLs (#113).
- Make server compatible with iRODS 5 (#142).
- Make DeleteObjectTagging operation return 501 (Not Implemented) (#152).

## [0.3.0] - 2024-10-03

### Changed

- Improve performance of Multipart Uploads (#114).
- Improve debug log messages (#124).
- Improve CMake (irods/irods#6251, irods/irods#6256, irods/irods#7265).

### Removed

- Remove unused header include for C++20 coroutines (#111).

### Fixed

- Server no longer enters infinite loop when listening socket is already bound (#96).
- Disable SIGPIPE signal for iRODS connections (#120).

### Added

- Implement AbortMultipartUpload operation (#109).
