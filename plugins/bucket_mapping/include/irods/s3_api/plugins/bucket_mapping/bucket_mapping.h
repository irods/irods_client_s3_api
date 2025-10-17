#ifndef IRODS_S3_API_BUCKET_MAPPING_PLUGIN_H
#define IRODS_S3_API_BUCKET_MAPPING_PLUGIN_H

/// \file

#include <stddef.h>

/// A structure representing a single mapping between a bucket name and
/// iRODS collection.
///
/// \since 0.5.0
typedef struct bucket_mapping_entry
{
	char* bucket;
	char* collection;
} bucket_mapping_entry_t;

#ifdef __cplusplus
extern "C" {
#endif

/// Initializes a bucket mapping plugin.
///
/// \param[in] _json The JSON string containing the configuration for the plugin.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int bucket_mapping_init(const char* _json);

/// List all bucket mappings.
///
/// On error, \p _buckets must be null and \p _size must be 0.
///
/// \param[out] _buckets The array holding all bucket mappings.
/// \param[out] _size    The number of elements in the array.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int bucket_mapping_list(bucket_mapping_entry_t** _buckets, size_t* _size);

/// Get the iRODS collection mapped to a bucket.
///
/// On error, \p _collection must be null.
///
/// \param[in]  _bucket     The bucket name.
/// \param[out] _collection The logical path of the mapped collection.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int bucket_mapping_collection(const char* _bucket, char** _collection);

/// Executes clean-up for the plugin.
///
/// \returns An integer indicating the status of the operation.
/// \retval 0        On success.
/// \retval non-zero On error.
///
/// \since 0.5.0
int bucket_mapping_close();

/// Deallocates memory allocated by the plugin.
///
/// If a null pointer is passed, the function does nothing.
///
/// \param[in] _data A pointer to memory allocated by the plugin.
///
/// \since 0.5.0
void bucket_mapping_free(void* _data);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_S3_API_BUCKET_MAPPING_PLUGIN_H
