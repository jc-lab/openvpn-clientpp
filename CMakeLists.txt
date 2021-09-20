cmake_minimum_required(VERSION 3.16)
project(openvpn-clientpp)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(cmake/common.cmake)

make_directory("${THIRDPARTIES_OUTPUT_DIR}/include")

message("CMAKE_GENERATOR : ${CMAKE_GENERATOR}")
message("CMAKE_GENERATOR_PLATFORM : ${CMAKE_GENERATOR_PLATFORM}")
message("CMAKE_GENERATOR_TOOLSET : ${CMAKE_GENERATOR_TOOLSET}")
message("CMAKE_GENERATOR_INSTANCE : ${CMAKE_GENERATOR_INSTANCE}")

add_subdirectory(jcu-unio)

add_subdirectory(thirdparty)
add_subdirectory(library)
#add_subdirectory(test)
