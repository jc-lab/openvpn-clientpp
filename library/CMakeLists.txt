add_library(openvpn_clientpp
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/log.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/client.h
        ${CMAKE_CURRENT_SOURCE_DIR}/inc/ovpnc/vpn_config.h

        ${CMAKE_CURRENT_SOURCE_DIR}/src/log.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/transport.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/transport.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/tcp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/tcp.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/udp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/udp.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/openssl_tls.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/openssl_tls.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/tls_layer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/tls_layer.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/reliable_layer.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/reliable_layer.cc

        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/base.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/reliable.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/reliable.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/control.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol/control.cc
        )

target_include_directories(
        openvpn_clientpp
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

add_dependencies(openvpn_clientpp uv_project)
target_link_libraries(
        openvpn_clientpp
        PUBLIC
        uv_a
        uvw-static
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
