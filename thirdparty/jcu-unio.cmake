if (NOT JCU_UNIO_FETCH_CONTENT_OPTIONS)
    set(JCU_UNIO_FETCH_CONTENT_OPTIONS
            GIT_REPOSITORY https://github.com/jc-lab/jcu-unio.git
            GIT_TAG        b1d338c709600f1c284e9c887ef0ee5c0f11dc63
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
