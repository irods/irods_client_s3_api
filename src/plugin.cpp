#include "./plugin.hpp"
#include "auth_plugin.h"
#include "bucket_plugin.h"

#include <dlfcn.h>
#include <iostream>
#include <fmt/format.h>

namespace irods::s3::plugins
{
    void load_plugin(rcComm_t& connection, const std::string_view& plugin_name, const nlohmann::json& configuration)
    {
        auto i = fmt::format("lib{}.so", plugin_name);
        void* plugin_handle = dlopen(i.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (plugin_handle == nullptr) {
            std::cerr << "Plugin library " << std::quoted(i) << " was not found by the linker" << std::endl;
        }
        void (*init)(rcComm_t*, const char*);

        // I love C :3
        *(void**) (&init) = dlsym(plugin_handle, "plugin_initialize");
        if (init == nullptr) {
            std::cerr << "Plugin library " << std::quoted(i)
                      << " does not contain an exported 'plugin_initialize' symbol." << std::endl;
        }
        auto dump = configuration.dump();
        (*init)(&connection, dump.c_str());
    }
} //namespace irods::s3::plugins
