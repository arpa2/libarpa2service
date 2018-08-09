include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable (testnai.test
	${CMAKE_SOURCE_DIR}/src/nai.c		#external path
	${CMAKE_CURRENT_SOURCE_DIR}/nai.c)	#overzealous local path for clarity
target_link_libraries (testnai.test
	arpa2aclStatic)

add_executable (naiverify.test
       ${CMAKE_SOURCE_DIR}/src/naiverify.c     # external path
       ${CMAKE_SOURCE_DIR}/src/nai.c)          # external path

add_test (testnai
	testnai.test)
add_test (naiverify
	${CMAKE_CURRENT_SOURCE_DIR}/naiverify ${CMAKE_CURRENT_BINARY_DIR}/naiverify.test)

