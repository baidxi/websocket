cmake_minimum_required(VERSION 3.17)
project(websocket_svr C)

set(CMAKE_C_STANDARD 11)

include(FindPkgConfig)

pkg_check_modules (JSON_C REQUIRED json-c)

link_libraries(${JSON_C_LIBRARYS} ${JSON_C_LIBRARYS})
include_directories(${JSON_C_INCLUDE_DIRS} ${JSON_C_INCLUDE_DIRS})


link_libraries("pthread.so")
link_libraries("ssl.so")
link_libraries("crypto.so")
link_libraries("libubus.so")
link_libraries("libubox.so")
link_libraries("libjson-c.so")
link_libraries("libblobmsg_json.so")

IF (${CMAKE_BUILD_TYPE} STREQUAL Debug)
        MESSAGE("-- Adding Debug flags ...")
        ADD_DEFINITIONS(-DDEBUG)
        set(CMAKE_C_FLAGS, ${CMAKE_C_FLAGS} -O0 -ggdb)
ENDIF (${CMAKE_BUILD_TYPE} STREQUAL Debug)


# OPTION(DEFINE_DEBUG "Build with debug info" OFF)

# IF (DEFINE_DEBUG)
#         ADD_DEFINITIONS(-DDEBUG)
#         SET(CMAKE_BUILD_TYPE Debug)
# ENDIF(DEFINE_DEBUG)

add_executable(websocket_svr main.c socket.c socket.h hexdump.c hexdump.h common.h websocket.c websocket.h common.c http_parser.c http_parser.h base64.c base64.h package.c package.h
                ubus.c ubus.h)
install(TARGETS websocket_svr
        RUNTIME DESTINATION usr/bin
        )
