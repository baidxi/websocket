cmake_minimum_required(VERSION 3.17)
project(websocket C)

set(CMAKE_C_STANDARD 11)
link_libraries("pthread.so")
link_libraries("ssl.so")
link_libraries("crypto")
add_executable(websocket main.c socket.c socket.h hexdump.c hexdump.h common.h websocket.c websocket.h common.c http_parser.c http_parser.h base64.c base64.h package.c package.h)