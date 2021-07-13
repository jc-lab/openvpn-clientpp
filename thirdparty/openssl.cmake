set(OPENSSL_FETCH_INFO
        URL https://www.openssl.org/source/openssl-1.1.1k.tar.gz
        URL_HASH SHA256=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5
        )

set(OPENSSL_USE_STATIC_LIBS ON)

FetchContent_Declare(
        openssl
        GIT_REPOSITORY https://github.com/jc-lab/openssl-cmake.git
        GIT_TAG        b27e5db43cdfce0ab9268bb2dd35bb8dab19ff62
)
FetchContent_GetProperties(openssl)
if (NOT openssl_POPULATED)
    FetchContent_Populate(openssl)
    add_subdirectory(${openssl_SOURCE_DIR} ${openssl_BINARY_DIR})
endif ()
