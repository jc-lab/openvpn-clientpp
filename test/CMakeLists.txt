include(GoogleTest)
enable_testing()

add_executable(
        ovpnc_transport_test
        transport_test.cc
)
target_link_libraries(
        ovpnc_transport_test
        PUBLIC
        openvpn_clientpp
        gtest
        gtest_main
)
gtest_discover_tests(ovpnc_transport_test)

