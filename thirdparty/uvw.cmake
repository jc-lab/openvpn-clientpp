if (NOT UVW_GIT_TAG)
    set(UVW_GIT_TAG 58b299ee60d62386a2339dab3f99d30570b33085) # v2.9.0_libuv_v1.41
endif ()

ExternalProject_Add(
        uvw_project

        GIT_REPOSITORY https://github.com/skypjack/uvw.git
        GIT_TAG ${UVW_GIT_TAG}

        CMAKE_ARGS
        ${SUBPROJECTS_COMMON_CMAKE_ARGS}
        "-DFETCH_LIBUV=OFF"
        "-DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}"
        "-DCMAKE_C_FLAGS_DEBUG=${PROJECT_COMMON_FLAGS_DEBUG}"
        "-DCMAKE_C_FLAGS_RELEASE=${PROJECT_COMMON_FLAGS_RELEASE}"
        "-DCMAKE_C_FLAGS_RELWITHDEBINFO=${PROJECT_COMMON_FLAGS_RELEASE}"
        "-DCMAKE_CXX_FLAGS_DEBUG=${PROJECT_COMMON_FLAGS_DEBUG}"
        "-DCMAKE_CXX_FLAGS_RELEASE=${PROJECT_COMMON_FLAGS_RELEASE}"
        "-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${PROJECT_COMMON_FLAGS_RELEASE}"

        UPDATE_COMMAND ""
        PATCH_COMMAND ""
        TEST_COMMAND ""
)

add_library(uvw-static INTERFACE)
target_include_directories(
        uvw-static
        INTERFACE
        ${THIRDPARTIES_OUTPUT_DIR}/include
)

add_dependencies(uvw-static uvw_project)
