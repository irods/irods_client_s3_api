#define BRIDGE_PLUGIN
#include "persistence_plugin.h"
#include "sqlite3.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/// We can pretend this is sufficient for migration logic(it probably actually is).
/// This is distinct from the `schema_version` pragma in sqlite, as that is automatically
/// incremented with changes made to the schema
const int SCHEMA_VERSION = 1;

namespace
{

    std::mutex database_creation_mutex;

    void write_message_to_log(void* pdata, int errorcode, const char* message)
    {
        FILE* f = fopen("sqlite error.log", "a");
        fprintf(f, "Error code (%d) with message [%s]\n", errorcode, message);
        fclose(f);
    }
    /// Create the tables for the database, migrating it forwards if necessary
    void create_tables(sqlite3* connection)
    {
        // We very much don't need multiple migrations running at once.
        // Grabbing the mutex initially prevents other threads from
        // intermingling with this one.
        std::lock_guard<std::mutex> guard(database_creation_mutex);

        char* errormsg = nullptr;
        int current_version;
        auto capture_version = [](void* current_version, int column_count, char** column_values, char** column_names) {
            *(int*) current_version = strtol(column_values[0], nullptr, 10);
            // This may need error checking to ensure that it worked properly.
            // That shouldn't happen in this case, but you know how it goes.
            return SQLITE_OK;
        };
        // Pretty wild how this is a higher order function operating over each row huh?
        sqlite3_exec(connection, "PRAGMA user_version", capture_version, &current_version, &errormsg);
        if (current_version == SCHEMA_VERSION) {
            return;
        }
        int ec;
        if (current_version < 1) {
            ec = sqlite3_exec(
                connection,
                "CREATE TABLE IF NOT EXISTS key_values(key BLOB PRIMARY KEY, value BLOB)",
                nullptr,
                nullptr,
                &errormsg);
            if (ec != 0) {
            }
            ec = sqlite3_exec(
                connection,
                "CREATE TABLE IF NOT EXISTS multipart_uploads(id INTEGER PRIMARY KEY,"
                "                                             path TEXT UNIQUE,"
                "                                             user TEXT)",
                nullptr,
                nullptr,
                &errormsg);
            if (ec != 0) {
            }
            ec = sqlite3_exec(
                connection,
                "CREATE TABLE IF NOT EXISTS multipart_upload_parts(multipart_id INTEGER,"
                "                                                  part_number  INTEGER,"
                "                                                  PRIMARY KEY(multipart_id,part_number),"
                "                                                  FOREIGN KEY(multipart_id)"
                "                                                          REFERENCES id)",
                nullptr,
                nullptr,
                &errormsg);
            if (ec != 0) {
                std::cout << sqlite3_errmsg(connection) << std::endl;
            }
            // Update the schema to avoid rerunning this version.
            ec = sqlite3_exec(connection, "PRAGMA user_version=1", nullptr, nullptr, &errormsg);
            if (ec != 0) {
            }
        }
    }
    bool store_key_value(sqlite3* db, const char* key, size_t key_length, const char* value, size_t value_length)
    {
        sqlite3_stmt* inserter;
        sqlite3_prepare_v2(db, "INSERT INTO key_values values (?,?)", -1, &inserter, nullptr);
        sqlite3_bind_text(inserter, 0, key, key_length, nullptr);
        sqlite3_bind_blob(inserter, 1, value, value_length, nullptr);
        sqlite3_step(inserter);
        sqlite3_reset(inserter);
        sqlite3_finalize(inserter);
        return true;
    }
    bool get_key_value(sqlite3* db, const char* key, size_t key_length, char** value, size_t* value_length)
    {
        sqlite3_stmt* selector;
        sqlite3_prepare_v2(db, "SELECT value FROM key_values WHERE key = ?", -1, &selector, nullptr);
        sqlite3_bind_text(selector, 0, key, key_length, nullptr);
        sqlite3_step(selector);
        size_t length = sqlite3_column_bytes(selector, 0);
        auto result = sqlite3_column_blob(selector, 0);
        *value = (char*) malloc(length);
        *value_length = length;
        memcpy(*value, result, length);

        sqlite3_reset(selector);
        sqlite3_finalize(selector);
        return true;
    }

    /// Create a new multipart upload and obtain an unused ID for it.
    /// \returns The new upload id, or a nullptr when the creation fails.
    char* create_multipart_upload(rcComm_t* connection, sqlite3* db, const std::string_view& path)
    {
        sqlite3_stmt* insertion;
        int ec;

        // For safety purposes we need to prepare a statement to insert here.

        ec = sqlite3_prepare_v2(db, "INSERT INTO multipart_uploads(path,user) values (?,?)", -1, &insertion, nullptr);
        if (ec != SQLITE_OK) {
            sqlite3_finalize(insertion);
            // Make a big noise when it falls over
            throw "AAAAA";
            // TODO error handling here.
            return nullptr;
        }
        // The binding requires the number of bytes in it, rather than the number of characters in the string.
        // I understand that the null character is meant to be included in this, but sqlite3 isn't very picky about
        // differences between BLOB and TEXT objects.
        // Well, not by default at least 😉
        ec = sqlite3_bind_text(
            insertion, 0, connection->clientUser.userName, strlen(connection->clientUser.userName) + 1, nullptr);
        if (ec != SQLITE_OK) {
        }
        ec = sqlite3_bind_text(insertion, 1, path.data(), path.length() + 1, nullptr);
        if (ec != SQLITE_OK) {
        }

        // This is where the insertion is actually performed.
        ec = sqlite3_step(insertion);
        if (ec != SQLITE_OK) {
            // Do something you something or other
        }

        sqlite3_reset(insertion);
        sqlite3_finalize(insertion);
        char* result_id = nullptr;
        sqlite3_exec(
            db,
            "select last_insert_rowid()",
            [](void* result_id, int columns, char** column_values, char** column_names) {
                *static_cast<char**>(result_id) = strdup(column_values[0]);
                return SQLITE_OK;
            },
            &result_id,
            nullptr);
        return result_id;
    }
    bool create_upload_part(
        rcComm_t* connection,
        sqlite3* db,
        const std::string_view& upload_id,
        const std::string_view& part_id)
    {
        sqlite3_stmt* insertion;
        int ec = sqlite3_prepare_v2(
            db,
            "INSERT INTO MULTIPART_UPLOAD_PARTS(multipart_id, part_number)"
            "            VALUES(?,?)",
            -1,
            &insertion,
            nullptr);
        if (ec != SQLITE_OK) {
            return false;
        }
        // The sqlite type system performs conversions to the column type if possible.
        // if this is a problem in practice, then we can look at changing the table declarations to be
        // strict[1], which will result in anything that cannot be converted to the column type
        // triggering an SQLITE_CONSTRAINT_DATATYPE error.
        // [1] that will look like `CREATE TABLE multipart_upload_parts(multipart_id INTEGER, part_number INTEGER)
        // STRICT`
        ec = sqlite3_bind_text(insertion, 0, upload_id.data(), upload_id.length() + 1, nullptr);
        if (ec != SQLITE_OK) {
        }
        ec = sqlite3_bind_text(insertion, 1, part_id.data(), part_id.length() + 1, nullptr);
        if (ec != SQLITE_OK) {
        }
        ec = sqlite3_step(insertion);
        if (ec != SQLITE_OK) {
        }
        sqlite3_reset(insertion);
        sqlite3_finalize(insertion);
        return true;
    }
    /// Retrieve the uploaded parts of a given multipart upload.
    /// \param connection The connection to the irods server
    /// \param db The connection to the sqlite3 database
    /// \param id The multipart upload id to find the parts of.
    /// \returns std::nullopt in the case where no parts exist, or a list of part numbers that have been uploaded.
    std::optional<std::vector<std::string>> list_parts(rcComm_t* connection, sqlite3* db, const std::string_view& id)
    {
        // TODO Optionally check on whether or not the user is actually the same as the multipart upload's

        // It may be prudent in the future to also mark this thread_local
        // as it should be able to be reused.
        sqlite3_stmt* get_parts;

        int ec = sqlite3_prepare_v2(
            db, "SELECT part_number FROM multipart_upload_parts WHERE id = ?", -1, &get_parts, nullptr);

        std::vector<std::string> parts;

        ec = sqlite3_bind_text(get_parts, 0, id.data(), id.length(), nullptr);
        if (ec != SQLITE_OK) {
            //
        }
        for (int rc = sqlite3_step(get_parts); rc != SQLITE_DONE; rc = sqlite3_step(get_parts)) {
            const char* result = (const char*) sqlite3_column_text(get_parts, 0);
            if (result) {
                parts.push_back(result);
            }
        }

        sqlite3_reset(get_parts);
        sqlite3_finalize(get_parts);

        if (parts.empty()) {
            return std::nullopt;
        }
        return parts;
    }

    bool
    list_multipart_uploads(rcComm_t* connection, sqlite3* db, multipart_listing_output** output, size_t* output_length)
    {
        sqlite3_stmt* upload_results;
        std::vector<multipart_listing_output> buffer;
        int ec = sqlite3_prepare_v2(
            db, "SELECT id, owner, path from multipart_uploads where owner = ?", -1, &upload_results, nullptr);
        ec = sqlite3_bind_text(upload_results, 0, connection->clientUser.userName, -1, nullptr);
        if (ec != SQLITE_OK) {
        }
        int rc;
        for (rc = sqlite3_step(upload_results); rc != SQLITE_DONE; rc = sqlite3_step(upload_results)) {
            buffer.emplace_back(multipart_listing_output{
                .owner = strdup((const char*) sqlite3_column_text(upload_results, 1)),
                .key = strdup((const char*) sqlite3_column_text(upload_results, 2)),
                .upload_id = strdup((const char*) sqlite3_column_text(upload_results, 0))});
        }
        sqlite3_reset(upload_results);
        sqlite3_finalize(upload_results);
        // sigh.
        *output = static_cast<multipart_listing_output*>(malloc(sizeof(multipart_listing_output) * buffer.size()));
        *output_length = buffer.size();

        memcpy(*output, buffer.data(), sizeof(multipart_listing_output) * buffer.size());
        return true;
    }
    /// Delete the database contents relating to a given upload as an abort.
    /// \param connection The connection to the irods server
    /// \param db the database connection
    /// \param id The upload id to abort
    /// \returns true on success. false otherwise
    bool abort_multipart_upload(rcComm_t* connection, sqlite3* db, const std::string_view& id)
    {
        sqlite3_stmt *delete_parts, *delete_upload;
        // smh at the dances we do to avoid sql injection
        sqlite3_prepare_v2(db, "DELETE FROM multipart_upload_parts WHERE upload_id = ?", -1, &delete_parts, nullptr);
        sqlite3_prepare_v2(db, "DELETE FROM multipart_uploads where id = ?", -1, &delete_upload, nullptr);
        sqlite3_bind_text(delete_parts, 0, id.data(), id.length(), nullptr);
        sqlite3_bind_text(delete_upload, 0, id.data(), id.length(), nullptr);
        sqlite3_step(delete_parts);
        sqlite3_step(delete_upload);
        sqlite3_reset(delete_parts);
        sqlite3_reset(delete_upload);
        sqlite3_finalize(delete_parts);
        sqlite3_finalize(delete_upload);
        return true;
    }

    // This may need revisiting, or not. It's hard to say, after all,
    // regardless of whether or not the upload is completed or aborted
    // the same thing happens in the database, and specifying
    // parts here doesn't make a difference.
    bool complete_multipart_upload(rcComm_t* connection, sqlite3* db, const std::string_view& id)
    {
        return abort_multipart_upload(connection, db, id);
    }

    bool get_path(rcComm_t* connection, sqlite3* db, const char* upload_id, char** path)
    {
        sqlite3_stmt* select_path;
        int ec = sqlite3_prepare_v2(db, "SELECT * FROM multipart_uploads where id = ?", -1, &select_path, nullptr);
        if (ec != SQLITE_OK) {
        }
        sqlite3_bind_text(select_path, 0, upload_id, -1, nullptr);
        for (int rc = sqlite3_step(select_path); rc != SQLITE_DONE; rc = sqlite3_step(select_path)) {
            *path = strdup((const char*) sqlite3_column_text(select_path, 0));
            sqlite3_finalize((select_path));
            return true;
        }
        sqlite3_finalize((select_path));
        return false;
    }

    /// Obtain a handle to the database, specific to the thread that acquires it.
    /// The connection should not be closed manually as it should be closed with the program, and thus this sets
    /// an atexit call for it.
    /// the program is terminated(assuming it terminates from a sigterm rather than a sigkill or sigsegv)
    sqlite3* initialize_db()
    {
        // The idea is that each thread of the runtime only needs one connection
        // and that it only needs to be initialized once, so we can avoid all these
        // goofy calls when we can avoid them
        static thread_local sqlite3* connection = nullptr;

        if (not connection) {
            int ec = sqlite3_open_v2(
                "s3-bridge.db",
                &connection,
                // Permit opening it or creating the database. Do not permit opening symbolic links.
                // Open the database with extended error codes enabled.
                SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_EXRESCODE,
                // Use the default virtual filesystem, we're not doing anything that needs that, I hope
                nullptr);

            // This is horrific, but necessary to prevent errors from the wal-file
            // not being cleaned up, so it's worth it I think.
            atexit([]() { sqlite3_close_v2(initialize_db()); });

            if (ec != SQLITE_OK) {
                throw sqlite3_errmsg(connection);
            }

            // This setting substantially improves disk IO characteristics and reduces
            // the number of fsync calls necessary.
            // It also helps prevent readers from blocking writers and visa-versa.
            // See https://www.sqlite.org/wal.html for details
            sqlite3_exec(connection, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);

            // Set a reasonable timeout for queries to be reattempted.
            // 100ms plus or minus some change seems reasonable enough
            sqlite3_busy_timeout(connection, 100 + random() % 20);

            // Finally with all that done, make the tables.
            create_tables(connection);
        }

        return connection;
    }

} // namespace
extern "C" void plugin_initialize(rcComm_t* connection, const char* config)
{
    nlohmann::json configuration = config;
    sqlite3_config(SQLITE_CONFIG_LOG, write_message_to_log, nullptr);
    initialize_db();
    add_persistence_plugin(
        [](rcComm_t* connection, const char* resolved_bucket_path, size_t* upload_id_length, char** upload_id) {
            *upload_id = create_multipart_upload(connection, initialize_db(), resolved_bucket_path);
            return upload_id != nullptr;
        },
        [](rcComm_t* connection,
           const char* upload_id,
           size_t* part_count,
           const char** parts,
           const char** part_checksums) {
            // Complete upload
            return complete_multipart_upload(connection, initialize_db(), upload_id);
        },
        [](rcComm_t* connection, const char* upload_id) {
            //abort upload
            return abort_multipart_upload(connection, initialize_db(), upload_id);
        },
        [](rcComm_t* connection, const char* upload_id, size_t* part_count, char*** parts) {
            // list parts
            auto c = list_parts(connection, initialize_db(), upload_id);
            if (c.has_value()) {
                *parts = (char**) malloc(sizeof(char*) * c.value().size());
                int j = 0;
                for (const auto& i : c.value()) {
                    // This feels gross from a performance perspective.
                    // probably worth evaluating having the list_parts function
                    // just write to a char** array directly the first time instead
                    // of using std::vector and std::string
                    (*parts)[j] = strdup(i.data());
                }
            }
            return c.has_value();
        },
        [](rcComm_t* connection, multipart_listing_output** multipart_uploads, size_t* multipart_count) {
            // list multipart uploads
            return list_multipart_uploads(connection, initialize_db(), multipart_uploads, multipart_count);
        },
        [](rcComm_t* connection, const char* upload_id, char** path) {
            return get_path(connection, initialize_db(), upload_id, path);
        },
        [](const char* key, size_t key_length, const char* value, size_t value_length) {
            return store_key_value(initialize_db(), key, key_length, value, value_length);
        },
        [](const char* key, size_t key_length, char** value, size_t* value_length) {
            return get_key_value(initialize_db(), key, key_length, value, value_length);
        });
}
