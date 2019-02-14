### Finds lmdb (Lightning Memory-Mapped Database)
#
#  LMDB_FOUND          - True if lmdb is found.
#  LMDB_INCLUDE_DIR    - Directory to include to get lmdb headers
#  LMDB_LIBRARY        - Library to link against for lmdb
#
include(CheckLibraryExists)
include(FeatureSummary)

set_package_properties(LMDB PROPERTIES
  DESCRIPTION "lmdb backend"
  URL "https://symas.com/lmdb/"
)

if(LMDB_INCLUDE_DIR AND LMDB_LIBRARY)
  # Already in cache, be silent
  set(LMDB_FIND_QUIETLY TRUE)
endif()

### Look for the header file.
#
# Do it once with hints and no default, so that a version
# installed in the hints paths will be preferred over a system version.
#
find_path(
  LMDB_INCLUDE_DIR
  NAMES lmdb.h
  HINTS /usr/local/include
  DOC "Include directory for lmdb"
  NO_DEFAULT_PATH
)
if(NOT LMDB_INCLUDE_DIR)
  find_path(
    LMDB_INCLUDE_DIR
    NAMES lmdb.h
    DOC "Include directory for lmdb"
  )
endif()
mark_as_advanced(LMDB_INCLUDE_DIR)

### Look for the library.
#
# If it exists, check for mdb_txn_begin
find_library(
  LMDB_LIBRARY
  NAMES lmdb
  HINTS /usr/local/lib
  DOC "Libraries to link against for lmdb"
)
if (LMDB_LIBRARY)
  # The arguments to check_library_exists are weird
  check_library_exists(${LMDB_LIBRARY} mdb_txn_begin "" _have_lmdb)
  if (NOT _have_lmdb)
    if(LMDB_FIND_REQUIRED OR NOT LMDB_FIND_QUIETLY)
      message(STATUS "Found lmdb in ${LMDB_LIBRARY} but it is missing mdb_txn_begin")
    endif()
  endif()
endif()
mark_as_advanced(LMDB_LIBRARY)

# Copy the results to the output variables.
if(LMDB_INCLUDE_DIR AND LMDB_LIBRARY AND _have_lmdb)
  set(LMDB_FOUND 1)
else()
  set(LMDB_FOUND 0)
endif()

if(LMDB_FOUND)
  if(NOT LMDB_FIND_QUIETLY)
    message(STATUS "Found lmdb header files: ${LMDB_INCLUDE_DIR}")
    message(STATUS "Found lmdb libraries:    ${LMDB_LIBRARY}")
  endif()
else()
  if(LMDB_FIND_REQUIRED)
    message(FATAL_ERROR "Could not find lmdb")
  elseif(NOT LMDB_FIND_QUIETLY)
    message(STATUS "Optional package lmdb was not found")
  endif()
endif()
