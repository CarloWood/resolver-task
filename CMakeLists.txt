cmake_minimum_required( VERSION 3.12...3.16 )

project( resolver-task
         DESCRIPTION "AIStatefulTask submodule - asynchronous hostname resolver"
         LANGUAGES CXX
)

include( AICxxProject )

#==============================================================================
# DEPENDENCIES
#

hunter_add_package( farmhash )
find_package( farmhash)

add_subdirectory( dns/src )

#==============================================================================
# BUILD PROJECT
#

# This project is an OBJECT-library, used by other git submodules and the main project.
add_library( resolver-task_ObjLib OBJECT )

# Set SOURCE_DIR to the current directory.
set_property(
    TARGET     resolver-task_ObjLib
    PROPERTY   SOURCE_DIR       "${CMAKE_CURRENT_SOURCE_DIR}"
)

# The list of source files.
target_sources( resolver-task_ObjLib
    PRIVATE
        "AddressInfo.cxx"
        "AddrInfoLookup.cxx"
        "DnsResolver.cxx"
        "GetAddrInfo.cxx"
        "GetNameInfo.cxx"
        "Service.cxx"

        "AddressInfo.h"
        "AddrInfoLookup.h"
        "DnsResolver.h"
        "GetAddrInfo.h"
        "GetNameInfo.h"
        "NameInfoLookup.h"
        "Service.h"
)

# Required include search-paths.
get_target_property( CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES )
target_include_directories( resolver-task_ObjLib
    PUBLIC
        "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}" # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features( resolver-task_ObjLib
    PUBLIC cxx_std_17
)

# Set link dependencies.
target_link_libraries( resolver-task_ObjLib
    PUBLIC
        farmhash::farmhash
        dns::dns
        AICxx::statefultask
)

# Create an ALIAS target.
add_library( AICxx::resolver-task ALIAS resolver-task_ObjLib )
