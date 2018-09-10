# Build the ARPA2 Service Libraries twice: once shared, once static.
include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
	add_definitions(-DDEBUG)
endif()

install (DIRECTORY ../man/
	DESTINATION share/man/man1/
	FILES_MATCHING PATTERN "*.1")
install (DIRECTORY ../man/
	DESTINATION share/man/man3/
	FILES_MATCHING PATTERN "*.3")
