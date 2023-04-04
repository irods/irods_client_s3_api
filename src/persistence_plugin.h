#ifndef PERSISTENCE_PLUGIN_H
#define PERSISTENCE_PLUGIN_H
#include <irods/rcConnect.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

/// A function type to enable creating a multipart upload
typedef bool (*multipart_create_fn)(
    rcComm_t* connection,
    const char* resolved_bucket_path,
    size_t* upload_id_length,
    char** upload_id);

/// A function type to enable completing a multipart upload
/// The part_checksums are permitted to be nullptrs when the user trusts the irods server.
typedef bool (*multipart_complete_fn)(
    rcComm_t* connection,
    const char* upload_id,
    size_t* part_count,
    const char** parts,
    const char** part_checksums);

typedef bool (*multipart_abort_fn)(rcComm_t* connection, const char* upload_id);

/// A function meant to provide a list of the part ids for a given upload_id
///
typedef bool (*multipart_list_parts_fn)(rcComm_t* connection, const char* upload_id, size_t* part_count, char*** parts);

/// Amazon S3 upload listings are a bit more complicated than I expected
/// Each entry must come with the following information:
/// The owner, the key(path), and the upload_id.
///
/// All the other fields can be omitted or fabricated until need is shown.
typedef struct
{
    char* owner;
    char* key;
    char* upload_id;
} multipart_listing_output;

/// A function type for retrieving in-progress multipart uploads
/// Takes 3 arguments, the connection to the irods server, the double star character pointer to send a nice location in
/// memory to and the number of multipart uploads reported.
typedef bool (*multipart_list_uploads_fn)(
    rcComm_t* connection,
    multipart_listing_output** multipart_uploads,
    size_t* multipart_count);

typedef bool (*multipart_path_from_id_fn)(rcComm_t* connection, const char* upload_id, char** path);

// This is the more general mechanism that can be used for unforeseen needs.

/// A function that sets the value associated with a key from a (hopefully) persistent store.
typedef bool (*store_key_value_fn)(const char* key, size_t key_length, const char* value, size_t value_length);

/// A function that retrieves the value associated with a key from a persistent store.
typedef bool (*get_key_value_fn)(const char* key, size_t key_length, char** value, size_t* value_length);

#ifdef BRIDGE_PLUGIN
extern
#endif
    void add_persistence_plugin(
        multipart_create_fn,
        multipart_complete_fn,
        multipart_abort_fn,
        multipart_list_parts_fn,
        multipart_list_uploads_fn,
        multipart_path_from_id_fn,
        store_key_value_fn,
        get_key_value_fn);

/// Free a multipart listing from memory
#ifdef BRIDGE_PLUGIN
extern
#endif
    void
    free_multipart_result(multipart_listing_output*);
#ifdef __cplusplus
}
#endif
#endif // PERSISTENCE_PLUGIN_H
