#
# CMAKE SETUP (version, build style)
#
# SPDX-License-Identifier: ISC
# License-Filename: LICENSE
cmake_minimum_required (VERSION 3.3)
project ("ARPA2 Service Libraries" C)

#set (CMAKE_C_STANDARD 90)
#set (CMAKE_C_STANDARD_REQUIRED ON)

#include (FeatureSummary)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake)

#
# XXX don't require ARPA2CM just yet, we're still trying to grasp CMake in
# general.
#

#find_package (ARPA2CM 0.5 NO_MODULE)
#set_package_properties (ARPA2CM PROPERTIES
#	DESCRIPTION "CMake modules for ARPA2 projects"
#	TYPE REQUIRED
#	URL "https://github.com/arpa2/arpa2cm/"
#	PURPOSE "Required for the CMake build system of libarpa2service"
#)
#
#if (ARPA2CM_FOUND)
#	set (CMAKE_MODULE_PATH
#		${CMAKE_MODULE_PATH}
#		${CMAKE_SOURCE_DIR}/cmake
#		${ARPA2CM_MODULE_PATH}
#	)
#else()
#        feature_summary (WHAT ALL)
#	message (FATAL_ERROR "ARPA2CM is required.")
#endif()

#include (MacroEnsureOutOfSourceBuild)
#include (MacroAddUninstallTarget)
#include (MacroGitVersionInfo)
#include (MacroCreateConfigFiles)
#include (CMakeDependentOption)

#macro_ensure_out_of_source_build("Do not build Quick-DER in the source directory.")

#
# OPTIONS / BUILD SETTINGS
#
#get_version_from_git (libarpa2service 0.0)

option (NO_TESTING "Disable testing" OFF)
if (NOT NO_TESTING)
	enable_testing()
endif()

#
# Build the executables and libraries
#

# SRC

# In debug configurations, add compile flag.
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

add_definitions(-Wall -Wextra -pedantic)

find_package(lmdb)

if (LMDB_FOUND)
	set(acldb_SRC src/a2acl_dblmdb.c)
	set(acldb_INCLUDES ${LMDB_INCLUDE_DIR})
	set(acldb_LIBS ${LMDB_LIBRARY})
else()
	set(acldb_SRC src/a2acl_dbm.c)
	set(acldb_INCLUDES "")
	set(acldb_LIBS "")
endif()

add_library(a2acldb SHARED ${acldb_SRC})
add_library(a2aclShared SHARED src/a2acl.c)
add_library(a2idShared SHARED src/a2id.c)

add_executable(a2acl src/a2aclcli.c)
add_executable(a2idmatch src/a2idmatch.c)

target_include_directories(a2acldb PRIVATE ${acldb_INCLUDES})
target_link_libraries(a2acldb PUBLIC ${acldb_LIBS})

target_link_libraries(a2aclShared a2idShared a2acldb)
target_link_libraries(a2acl a2aclShared)
target_link_libraries(a2idmatch a2idShared)

# starting from CMake 3.14, drop DESTINATION and use platform defaults
install(TARGETS a2idShared a2aclShared a2acldb DESTINATION lib PUBLIC_HEADER DESTINATION include/arpa2)
install(TARGETS a2idmatch a2acl DESTINATION bin)
install(FILES src/a2id.h DESTINATION include/arpa2)
install(FILES src/a2acl.h DESTINATION include/arpa2)
# starting from CMake 3.14, use TYPE MAN... instead of DESTINATION
install(DIRECTORY doc/man/ DESTINATION share/man/man1 FILES_MATCHING PATTERN "*.1")
install(DIRECTORY doc/man/ DESTINATION share/man/man3 FILES_MATCHING PATTERN "*.3")

# TEST

# tests use no real db backend, but a mock
add_executable(testa2id test/testa2id.c src/a2id.c)
add_executable(testa2acl test/testa2acl.c src/a2acl.c src/a2id.c)

add_test(testa2id testa2id)
add_test(testa2idmatch ${CMAKE_CURRENT_SOURCE_DIR}/test/testa2idmatch ${CMAKE_CURRENT_BINARY_DIR}/a2idmatch)
add_test(testa2acl testa2acl)

#add_uninstall_target ()

#
# PACKAGING
#

set (CPACK_PACKAGE_NAME "ARPA2-ServiceLibs")
set (CPACK_PACKAGE_VERSION ${ARPA2-ServiceLibs_VERSION})
set (CPACK_PACKAGE_VENDOR "ARPA2.net")
set (CPACK_PACKAGE_CONTACT "Tim Kuijsten")
# License information for packaging. This uses the SPDX license
# identifiers from https://spdx.org/licenses/
set (CPACK_PACKAGE_LICENSE "ISC")

#include (PackAllPossible)
include (CPack)

#
# CMAKE CONFIGURATION FILES
#
# These make it simple to use find_package(Quick-DER) in other
# projects, because Quick-DER can be found (and version information
# obtained) automatically.
#
#TODO_NEED_PC_IN# create_config_files (ARPA2-ServiceLibs)
