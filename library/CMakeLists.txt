add_library(openvpn_clientpp
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/client.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/vpn_config.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/crypto/provider.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/crypto/cipher.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/crypto/auth.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/push_options.h

        ${CMAKE_CURRENT_SOURCE_DIR}/src/client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/push_options.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/reliable_layer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/reliable_layer.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/multiplexer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/multiplexer.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/buffer_with_header.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/buffer_with_header.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/receive_buffer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/receive_buffer.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/rw_buffer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/rw_buffer.cc

        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/base.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/reliable.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/reliable.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/control.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/control.cc

        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl_aes_gcm.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl_aes_gcm.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/null_digest.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/null_digest.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/default_provider.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/default_provider.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl_random.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/openssl_random.cc
        )

target_include_directories(
        openvpn_clientpp
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

target_link_libraries(
        openvpn_clientpp
        PUBLIC
        jcu_unio
        uv_a
        OpenSSL::Crypto
        OpenSSL::SSL
)
if (WIN32)
    target_link_libraries(
            openvpn_clientpp
            PUBLIC
            ws2_32
            iphlpapi
            userenv
    )
endif ()

add_executable(develop develop.cc)
target_link_libraries(develop PUBLIC openvpn_clientpp)
