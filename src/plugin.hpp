#ifndef IRODS_S3_API_PLUGIN_HPP
#define IRODS_S3_API_PLUGIN_HPP
#include <string_view>
#include <nlohmann/json.hpp>
#include <irods/rcConnect.h>

namespace irods::s3::plugins
{
    /// \brief Load a plugin
    ///
    /// Plugins in irods_s3_api are loaded as dynamic modules, after this, the program runs the symbol associated
    /// with `plugin_initialize`, which should be a function that accepts an `rcComm_t*` connection and a `const char*`
    /// configuration string which the plugin must parse on its own.
    ///
    /// In addition, the plugin must be in the LD search path.
    ///
    /// \param connection The connection to the irods server.
    /// \param plugin_name The name of the plugin, directly related to the plugin file
    /// \param configuration The configuration text to pass to the plugin.
    void load_plugin(rcComm_t& connection, const std::string_view& plugin_name, const nlohmann::json& configuration);

    /// \brief Checks if an authentication plugin is loaded.
    bool authentication_plugin_loaded();

    /// \brief Checks if a bucket resolution plugin is loaded
    bool bucket_plugin_loaded();
} //namespace irods::s3::plugins
#endif // IRODS_S3_API_PLUGIN_HPP
