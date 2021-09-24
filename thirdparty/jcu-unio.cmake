if (NOT JCU_UNIO_FETCH_CONTENT_OPTIONS)
    set(JCU_UNIO_FETCH_CONTENT_OPTIONS
            GIT_REPOSITORY https://github.com/jc-lab/jcu-unio.git
            GIT_TAG        95bb7e2ddcd0dabb3025ae1f6e62749bbdbddce6
            )
endif ()

if (NOT TARGET jcu_unio)
    FetchContent_Declare(
            jcu_unio
            ${JCU_UNIO_FETCH_CONTENT_OPTIONS}
    )
    FetchContent_GetProperties(jcu_unio)
    if (NOT jcu_unio_POPULATED)
        FetchContent_Populate(jcu_unio)
    endif ()
    add_subdirectory(${jcu_unio_SOURCE_DIR} third_party/jcu_unio)
endif()
