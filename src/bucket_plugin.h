/// This contains the function type definitions used for bucket provider plugins
// Doing it ♪old school♫
#ifndef BUCKET_PLUGIN_H
#define BUCKET_PLUGIN_H
#include <stddef.h>
#include <irods/rcConnect.h>

// I think this kinda thing is sorta gross, but like, here we are dudes. 😎
#ifdef __cplusplus
extern "C" {
#endif

/// Takes 5 arguments, the connection to iRODS, the buffer string, and the length of that string,
/// the buffer to write to, and a storage location for the length of the string.
///
/// Return false when there is no bucket.
///
///
typedef bool (*bucket_resolution_function)(rcComm_t* connection, const char* bucket, char* output, size_t* length);

// TODO remove the bucket_reversal_function when possible, it should *not* be necessary

/// Takes 5 arguments, the connection to irods, the path, the output buffer, and the location to
/// place the output buffer.
///
/// Returns non-zero when it is able to reverse the bucket.
typedef bool (*bucket_reversal_function)(rcComm_t* connection, const char* path, char* output, size_t* output_length);

/// To be called when a bucket is requested to be created.
///
/// Takes two arguments, the connection, and the bucket's name
///
/// Returns 0 on success, but irods error codes otherwise.
typedef int (*bucket_creation_function)(rcComm_t* connection, const char* bucket);

/// To be called when a user wants to delete a bucket.
///
/// Takes two arguments, the connection and the name of the bucket.
/// Returns 0 on success, otherwise some irods permission error, I think
typedef int (*bucket_deletion_function)(rcComm_t* connection, const char* bucket);

/// To be called when the user wants to obtain a list of buckets.
///
/// Takes three arguments, the connection, and a pointer to a char** which will be
/// written to, the owning user's irod username, and an output pointer to a nullptr terminated
/// list of char*s
///
/// \remark A function that implements this should take care that memory allocations for the output
/// buffer are from an allocator compatible with free(1)
typedef int (*bucket_list_function)(rcComm_t* connection, const char* username, char*** output_buffer);

#ifdef BRIDGE_PLUGIN
extern
#endif
    /// To be called on s3_api_load
    ///
    /// @param resolution_f The bucket resolution function. This is the core of the plugin.
    /// @param reversal_f The bucket reversal function or the null pointer
    /// @param creation_f The bucket creation function or the null pointer
    /// @param deletion_f The bucket deletion function or the null pointer
    /// @param list_f The bucket list function or the null pointer
    void
    add_bucket_plugin(
        bucket_resolution_function resolution_f,
        bucket_reversal_function reversal_f,
        bucket_creation_function creation_f,
        bucket_deletion_function deletion_f,
        bucket_list_function list_f);

#ifdef __cplusplus
}
#endif
#endif // BUCKET_PLUGIN_H
