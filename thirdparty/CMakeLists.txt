if (MSVC)
    add_compile_options(/utf-8)
endif ()

set(SUBPROJECTS_COMMON_CMAKE_ARGS "-G" "${CMAKE_GENERATOR}")
if (${CMAKE_VS_PLATFORM_NAME})
    list(APPEND SUBPROJECTS_COMMON_CMAKE_ARGS "-A" "${CMAKE_VS_PLATFORM_NAME}")
endif()

list(APPEND SUBPROJECTS_COMMON_CMAKE_ARGS
        "-DOVPNC_SUB_PROJECT=TRUE"
        "-DCMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}"
        "-DTHIRDPARTIES_OUTPUT_DIR=${THIRDPARTIES_OUTPUT_DIR}"
        "-DCMAKE_INSTALL_PREFIX=${THIRDPARTIES_OUTPUT_DIR}"
        )

include(FetchContent)
include(ExternalProject)

include(gtest.cmake)
include(openssl.cmake)
include(uv.cmake)
include(uvw.cmake)
