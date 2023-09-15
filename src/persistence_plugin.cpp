#include "plugin.hpp"
#include "persistence_plugin.h"
#include "persistence.hpp"
#include "multipart.hpp"

namespace
{
    struct persistence_plugin
    {
        multipart_create_fn create_fn;
        multipart_complete_fn complete_fn;
        multipart_abort_fn abort_fn;
        multipart_list_parts_fn list_parts_fn;
        multipart_list_uploads_fn list_uploads_fn;
        multipart_path_from_id_fn get_path_fn;
        store_key_value_fn store_key_fn;
        get_key_value_fn get_key_value_fn;
    } active_persistence_plugin;
} //namespace

void add_persistence_plugin(
    multipart_create_fn create_fn,
    multipart_complete_fn complete_fn,
    multipart_abort_fn abort_fn,
    multipart_list_parts_fn list_parts_fn,
    multipart_list_uploads_fn list_uploads_fn,
    multipart_path_from_id_fn get_path_fn,
    store_key_value_fn store_key_fn,
    get_key_value_fn get_value_fn)
{
    active_persistence_plugin = persistence_plugin{
        create_fn, complete_fn, abort_fn, list_parts_fn, list_uploads_fn, get_path_fn, store_key_fn, get_value_fn};
}

void free_multipart_result(multipart_listing_output* c)
{
    std::free(c->key);
    std::free(c->owner);
    std::free(c->upload_id);
}

namespace irods::s3
{
    /// Create a new multipart upload.
    /// \param connection The connection to the iRODS server
    /// \param path The path to create the upload at.
    /// \returns The ID of the multipart upload
    std::optional<std::string> create_multipart_upload(rcComm_t* connection, const std::string_view& path)
    {
        // Create directory for parts
        // add it to the persistent store.
        auto directory_path = irods::s3::multipart::utilities::get_temporary_file(path, "");
        char* upload_id;
        size_t upload_id_length;
        if (not active_persistence_plugin.create_fn(connection, path.data(), &upload_id_length, &upload_id)) {
            // Not *exactly* sure how to handle this
        }
        return std::string(std::string_view(upload_id, upload_id_length));
    }

    /// Finish a multipart upload, concatenating the files together.
    /// \param connection The connection to the iRODS server
    /// \param the final path of the multipart upload
    /// \param part_ids the list of part_ids specified to include in the finished file.
    bool complete_multipart_upload(
        rcComm_t* connection,
        const std::string_view& path,
        const std::vector<std::string>& part_ids)
    {
        // TODO
        return false;
    }

    /// Abort a multipart upload, deleting all partial uploads associated with it.
    /// \param connection The connection to the irods server.
    /// \param path The path of the upload.
    bool abort_multipart_upload(rcComm_t* connection, const std::string_view& path)
    {
        // TODO
        return false;
    }

    std::optional<std::string>
    create_part(rcComm_t* connection, const std::string_view& upload_id, const std::string_view& part)
    {
        char* path;
        if (!active_persistence_plugin.get_path_fn(connection, upload_id.data(), &path)) {
            return std::nullopt;
        }
        auto ret = irods::s3::multipart::utilities::get_temporary_file(path, part);
        free(path);
        return ret;
    }

    std::vector<std::string> list_multipart_upload_parts(rcComm_t* connection, const std::string_view& upload_id)
    {
        // Careful listeners may have noticed that you can almost certainly avoid using the persistence plugin at all.
        //
        char** parts;
        size_t part_count;
        active_persistence_plugin.list_parts_fn(connection, upload_id.data(), &part_count, &parts);
        std::vector<std::string> results;
        for (size_t i = 0; i < part_count; i++) {
            char* c = parts[i];
            results.emplace_back(c);
            free(c); // Watch this space, it might explode
        }
        free(parts);
        return results;
    }

    std::vector<std::string> list_multipart_uploads(rcComm_t* connection)
    {
        // TODO
        std::vector<std::string> v;
        return v;
    }
} //namespace irods::s3
