#ifndef IRODS_S3_API_USER_MAPPING_PLUGIN_H
#define IRODS_S3_API_USER_MAPPING_PLUGIN_H

/// \file

#ifdef __cplusplus
extern "C" {
#endif

/// Initializes a user mapping plugin.
///
/// \param[in] _json The JSON string containing the configuration for the plugin.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int user_mapping_init(const char* _json);

/// Get the iRODS username mapped to a S3 access key ID.
///
/// On error, \p _irods_username must be null.
///
/// \param[in]  _s3_access_key_id The key ID used for lookup.
/// \param[out] _irods_username   The iRODS username mapped to the key ID. Will be
///                               NULL if the key ID doesn't exist.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int user_mapping_irods_username(const char* _s3_access_key_id, char** _irods_username);

/// Get the S3 secret key associated with a S3 access key ID.
///
/// On error, \p _s3_secret_key must be null.
///
/// \param[in]  _s3_access_key_id The key ID used for lookup.
/// \param[out] _s3_secret_key    The secret key associated with the key ID. Will be
///                               NULL if the key ID doesn't exist.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int user_mapping_s3_secret_key(const char* _s3_access_key_id, char** _s3_secret_key);

/// Executes clean-up for the plugin.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int user_mapping_close();

/// Deallocates memory allocated by the plugin.
///
/// If a null pointer is passed, the function does nothing.
///
/// \param[in] _data A pointer to memory allocated by the plugin.
///
/// \since 0.5.0
void user_mapping_free(void* _data);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_S3_API_USER_MAPPING_PLUGIN_H
