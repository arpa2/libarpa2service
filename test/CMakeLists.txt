include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable (testa2id
	${CMAKE_SOURCE_DIR}/src/a2id.c		#external path
	${CMAKE_CURRENT_SOURCE_DIR}/testa2id.c)	#overzealous local path for clarity

target_link_libraries (testa2id
	arpa2idStatic)

add_test (testa2id
	testa2id)

add_test (testa2idmatch
	${CMAKE_CURRENT_SOURCE_DIR}/testa2idmatch
	${CMAKE_CURRENT_BINARY_DIR}/../src/a2idmatch)
