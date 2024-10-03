# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project **only** adheres to the following _(as defined at [Semantic Versioning](https://semver.org/spec/v2.0.0.html))_:

> Given a version number MAJOR.MINOR.PATCH, increment the:
> 
> - MAJOR version when you make incompatible API changes
> - MINOR version when you add functionality in a backward compatible manner
> - PATCH version when you make backward compatible bug fixes

## [0.3.0] - 2024-10-03

### Added

- Implement AbortMultipartUpload operation (#109).

### Changed

- Improve performance of Multipart Uploads (#114).
- Improve debug log messages (#124).
- Improve CMake (irods/irods#6251, irods/irods#6256, irods/irods#7265).

### Removed

- Remove unused header include for C++20 coroutines (#111).

### Fixed

- Server no longer enters infinite loop when listening socket is already bound (#96).
- Disable SIGPIPE signal for iRODS connections (#120).
