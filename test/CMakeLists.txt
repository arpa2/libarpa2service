include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable (testnai.test
	${CMAKE_SOURCE_DIR}/src/nai.c		#external path
	${CMAKE_CURRENT_SOURCE_DIR}/testnai.c)	#overzealous local path for clarity
target_link_libraries (testnai.test
	arpa2aclStatic)

add_executable (testa2donai.test
	${CMAKE_SOURCE_DIR}/src/a2donai.c		#external path
	${CMAKE_CURRENT_SOURCE_DIR}/testa2donai.c)	#overzealous local path for clarity
target_link_libraries (testa2donai.test
	arpa2aclStatic)

add_executable (naiverify.test
       ${CMAKE_SOURCE_DIR}/src/naiverify.c     # external path
       ${CMAKE_SOURCE_DIR}/src/nai.c)          # external path

add_test (testnai
	testnai.test)
add_test (testa2donai
	testa2donai.test)
add_test (testnaiverify
	${CMAKE_CURRENT_SOURCE_DIR}/testnaiverify ${CMAKE_CURRENT_BINARY_DIR}/naiverify.test)

