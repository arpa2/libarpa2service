#
# CMAKE SETUP (version, build style)
#
# SPDX-License-Identifier: ISC
# License-Filename: LICENSE
cmake_minimum_required (VERSION 3.1 FATAL_ERROR)
project ("ARPA2 Service Libraries" C)

set (CMAKE_C_STANDARD 90)
set (CMAKE_C_STANDARD_REQUIRED ON)

include (FeatureSummary)
find_package (ARPA2CM 0.5 NO_MODULE)
set_package_properties (ARPA2CM PROPERTIES
	DESCRIPTION "CMake modules for ARPA2 projects"
	TYPE REQUIRED
	URL "https://github.com/arpa2/arpa2cm/"
	PURPOSE "Required for the CMake build system of libarpa2service"
)

if (ARPA2CM_FOUND)
	set (CMAKE_MODULE_PATH
		${CMAKE_MODULE_PATH}
		${CMAKE_SOURCE_DIR}/cmake
		${ARPA2CM_MODULE_PATH}
	)
else()
        feature_summary (WHAT ALL)
	message (FATAL_ERROR "ARPA2CM is required.")
endif()

include (MacroEnsureOutOfSourceBuild)
include (MacroAddUninstallTarget)
include (MacroGitVersionInfo)
include (MacroCreateConfigFiles)
include (CMakeDependentOption)

macro_ensure_out_of_source_build("Do not build Quick-DER in the source directory.")

#
# OPTIONS / BUILD SETTINGS
#
option (DEBUG
	"Produce verbose output while unpacking and packing DER"
	ON)
option (NO_TESTING
	"Disable testing."
	OFF)
get_version_from_git (libarpa2service 0.0)

if (NOT NO_TESTING)
	enable_testing ()
endif()

#
# BUILDING
#
add_subdirectory (src)
add_subdirectory (man)
add_subdirectory (test)

add_uninstall_target ()

#
# PACKAGING
#

set (CPACK_PACKAGE_NAME "ARPA2-ServiceLibs")
set (CPACK_PACKAGE_VERSION ${ARPA2-ServiceLibs_VERSION})
set (CPACK_PACKAGE_VENDOR "ARPA2.net")
set (CPACK_PACKAGE_CONTACT "Tim Kuijsten <tim@netsend.nl>")
# License information for packaging. This uses the SPDX license
# identifiers from https://spdx.org/licenses/
set (CPACK_PACKAGE_LICENSE "ISC")

include (PackAllPossible)
include (CPack)

#
# CMAKE CONFIGURATION FILES
#
# These make it simple to use find_package(Quick-DER) in other
# projects, because Quick-DER can be found (and version information
# obtained) automatically.
#
#TODO_NEED_PC_IN# create_config_files (ARPA2-ServiceLibs)

