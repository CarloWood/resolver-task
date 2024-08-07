cmake_minimum_required(VERSION 3.15...3.30)

project(resolver-task
  DESCRIPTION "AIStatefulTask submodule - asynchronous hostname resolver"
  LANGUAGES CXX
)

include(AICxxProject)

#==============================================================================
# DEPENDENCIES
#

find_package(farmhash REQUIRED)

add_subdirectory(dns/src)

#==============================================================================
# BUILD PROJECT
#

# This project is an OBJECT-library, used by other git submodules and the main project.
add_library(resolver-task_ObjLib OBJECT)

# The list of source files.
target_sources(resolver-task_ObjLib
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
get_target_property(CWDS_INTERFACE_INCLUDE_DIRECTORIES AICxx::cwds INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(resolver-task_ObjLib
  PUBLIC
    "${CWDS_INTERFACE_INCLUDE_DIRECTORIES}"     # For sys.h and debug.h.
)

# Require support for C++17.
target_compile_features(resolver-task_ObjLib
  PUBLIC cxx_std_17
)

# Set link dependencies.
target_link_libraries(resolver-task_ObjLib
  PUBLIC
    farmhash::farmhash
    dns::dns
    AICxx::statefultask
)

# Create an ALIAS target.
add_library(AICxx::resolver-task ALIAS resolver-task_ObjLib)
