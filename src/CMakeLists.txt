# Build the ARPA2 Service Libraries twice: once shared, once static.
include_directories (.)

# Forward the CMake option to the compiler
if (DEBUG)
	add_definitions(-DDEBUG)
endif()

add_definitions(-Wall -Wextra -pedantic)

set(arpa2id_SRC
	a2id.c
)

# set(arpa2kv_SRC
# )
# 
# set(arpa2sigid_SRC
# )
# 
# set(arpa2group_SRC
# )

add_executable(a2idmatch
	a2idmatch.c ${arpa2id_SRC})

add_library(arpa2idShared SHARED ${arpa2id_SRC})
set_target_properties(arpa2idShared
	PROPERTIES OUTPUT_NAME arpa2id)

add_library(arpa2idStatic STATIC ${arpa2id_SRC})
set_target_properties(arpa2idStatic
	PROPERTIES OUTPUT_NAME arpa2id)

# add_library(arpa2kvShared SHARED ${arpa2kv_SRC})
# set_target_properties(arpa2kvShared
# 	PROPERTIES OUTPUT_NAME arpa2kv)
# 
# 
# add_library(arpa2kvStatic STATIC ${arpa2kv_SRC})
# set_target_properties(arpa2kvStatic
# 	PROPERTIES OUTPUT_NAME arpa2kv)
# 
# 
# add_library(arpa2signidShared SHARED ${arpa2signid_SRC})
# set_target_properties(arpa2signidShared
# 	PROPERTIES OUTPUT_NAME arpa2signid)
# 
# add_library(arpa2signidStatic STATIC ${arpa2signid_SRC})
# set_target_properties(arpa2signidStatic
# 	PROPERTIES OUTPUT_NAME arpa2signid)
# 
# 
# add_library(arpa2groupShared SHARED ${arpa2group_SRC})
# set_target_properties(arpa2groupShared
# 	PROPERTIES OUTPUT_NAME arpa2group)
# 
# add_library(arpa2groupStatic STATIC ${arpa2group_SRC})
# set_target_properties(arpa2groupStatic
# 	PROPERTIES OUTPUT_NAME arpa2group)


install (TARGETS a2idmatch
	RUNTIME DESTINATION bin)
install (TARGETS arpa2idShared #arpa2kvShared arpa2signidStatic arpa2groupShared
	LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include/arpa2)
install (TARGETS arpa2idStatic #arpa2kvStatic arpa2signidStatic arpa2groupStatic
	ARCHIVE DESTINATION lib)
install (DIRECTORY ../src/
	DESTINATION include/arpa2/
	FILES_MATCHING PATTERN "*.h")
