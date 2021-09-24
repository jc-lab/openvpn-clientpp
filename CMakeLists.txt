cmake_minimum_required(VERSION 3.16)
project(openvpn-clientpp)

set(CMAKE_CXX_STANDARD 14)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(cmake/common.cmake)

make_directory("${THIRDPARTIES_OUTPUT_DIR}/include")

add_subdirectory(thirdparty)
add_subdirectory(library)
#add_subdirectory(test)
