#include <iostream>

#include <jcu-unio/loop.h>

#include <jcu-unio/net/openssl_provider.h>

#include <ovpnc/client.h>
#include <ovpnc/vpn_config.h>

#include <ovpnc/openssl_tls_provider.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

int mainWrapped() {
  auto logger = jcu::unio::createDefaultLogger([](auto &line) -> void {
    std::cout << line << std::endl;
  });

  auto loop = jcu::unio::UnsafeLoop::fromDefault();
  loop->init();

  std::shared_ptr<jcu::unio::openssl::OpenSSLProvider> openssl_provider = jcu::unio::openssl::OpenSSLProvider::create();
  auto openssl_context = openssl_provider->createOpenSSLContext(TLSv1_2_method()); // TLS_method()

  {
    SSL_CTX* ctx = openssl_context->getNativeCtx();

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    unsigned int ssl_ctx_mode =
        SSL_MODE_AUTO_RETRY |
            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
            SSL_MODE_ENABLE_PARTIAL_WRITE |
            SSL_MODE_RELEASE_BUFFERS;

    SSL_CTX_set_mode(
        ctx,
        ssl_ctx_mode
    );

    SSL_CTX_use_PrivateKey_file(ctx, "D:\\jcworkspace\\openvpn-cpp\\test\\client.key", SSL_FILETYPE_PEM);
    SSL_CTX_use_certificate_file(ctx, "D:\\jcworkspace\\openvpn-cpp\\test\\client.pem", SSL_FILETYPE_PEM);
  }

  auto client = ovpnc::Client::create(loop, logger);
  ovpnc::VPNConfig config { };
  config.ssl_context = openssl_context;
  config.protocol = ovpnc::kTransportTcp;
  config.remote_host = "192.168.44.136"; // 44.167
  config.remote_port = 61194;
//  config.remote_port = 61195;
  client->setAutoReconnect(true);
  client->connect(config);

  uv_run(loop->get(), UV_RUN_DEFAULT);
  loop->uninit();

  return 0;
}

int main() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  ERR_load_ERR_strings();

  return mainWrapped();
}



//2021-07-14T01:16:41+0900 [DEBUG] ReliableLayer: processPacketInbound: op_code=6, key_id=0, size=71
//2021-07-14T01:16:41+0900 [DEBUG] ReliableLayer: processPacketInbound: op_code=6: Not supported yet

/*
2021-07-14 01:16:32 TCP connection established with [AF_INET]192.168.1.10:27999
2021-07-14 01:16:32 192.168.1.10:27999 TLS: Initial packet from [AF_INET]192.168.1.10:27999, sid=3ff19432 cf3c9bdd
2021-07-14 01:16:32 192.168.1.10:27999 VERIFY OK: depth=1, C=KR, O=Test CA, OU=CA, CN=Test CA
2021-07-14 01:16:32 192.168.1.10:27999 VERIFY OK: depth=0, C=KR, O=Test CA, OU=VPN Client, CN=vpn client 01
2021-07-14 01:16:32 192.168.1.10:27999 WARNING: 'link-mtu' is used inconsistently, local='link-mtu 1543', remote='link-mtu 1500'
2021-07-14 01:16:32 192.168.1.10:27999 WARNING: 'auth' is used inconsistently, local='auth SHA1', remote='auth none'
2021-07-14 01:16:32 192.168.1.10:27999 WARNING: 'keysize' is used inconsistently, local='keysize 128', remote='keysize 0'
2021-07-14 01:16:32 192.168.1.10:27999 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 2048 bit RSA, signature: RSA-SHA256
2021-07-14 01:16:32 192.168.1.10:27999 [vpn client 01] Peer Connection Initiated with [AF_INET]192.168.1.10:27999
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not enabled)
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 MULTI: Learn: 10.8.0.6 -> vpn client 01/192.168.1.10:27999
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 MULTI: primary virtual IP for vpn client 01/192.168.1.10:27999: 10.8.0.6
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 Data Channel: using negotiated cipher 'AES-256-GCM'
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 Outgoing Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
2021-07-14 01:16:32 vpn client 01/192.168.1.10:27999 Incoming Data Channel: Cipher 'AES-256-GCM' initialized with 256 bit key
 */


/**
*
 * SSL INBOUND : data :
00 00 00 00 02 4c e1 3c 35 f1 19 4b 49 05 ea 0c 80 4f 29 da 15 c9 b5 8e 5c e6 9b f0 cc 31 f4 11 eb 74 4b 92 f3 3c fc e3
18 34 e6 5e 33 21 b5 13 77 aa c2 63 d2 a7 ac 17 5f 78 17 eb 40 14 17 d3 16 61 99 eb 32 00 6c 56 34 2c 64 65 76 2d 74 79
70 65 20 74 75 6e 2c 6c 69 6e 6b 2d 6d 74 75 20 31 35 34 33 2c 74 75 6e 2d 6d 74 75 20 31 35 30 30 2c 70 72 6f 74 6f 20
54 43 50 76 34 5f 53 45 52 56 45 52 2c 61 75 74 68 20 53 48 41 31 2c 6b 65 79 73 69 7a 65 20 31 32 38 2c 6b 65 79 2d 6d
65 74 68 6f 64 20 32 2c 74 6c 73 2d 73 65 72 76 65 72 00 00 00 00 00 00 00



 Literal 0 (4 bytes) : 00 00 00 00
 key_method_type : 02
 key_source : (random 1) 4c e1 3c 35 f1 19 4b 49 05 ea 0c 80 4f 29 da 15 c9 b5 8e 5c e6 9b f0 cc 31 f4 11 eb 74 4b 92 f3
              (random 1) 3c fc e3 18 34 e6 5e 33 21 b5 13 77 aa c2 63 d2 a7 ac 17 5f 78 17 eb 40 14 17 d3 16 61 99 eb 32
 options_string_length : 00 6c
 options_string : 56 34 2c 64 65 76 2d 74 79 70 65 20 74 75 6e 2c 6c 69 6e 6b
                  2d 6d 74 75 20 31 35 34 33 2c 74 75 6e 2d 6d 74 75 20 31 35
                  30 30 2c 70 72 6f 74 6f 20 54 43 50 76 34 5f 53 45 52 56 45
                  52 2c 61 75 74 68 20 53 48 41 31 2c 6b 65 79 73 69 7a 65 20
                  31 32 38 2c 6b 65 79 2d 6d 65 74 68 6f 64 20 32 2c 74 6c 73
                  2d 73 65 72 76 65 72 00
  00 00 / 00 00 / 00 00

  // V4,dev-type tun,link-mtu 1543,tun-mtu 1500,proto TCPv4_SERVER,auth SHA1,keysize 128,key-method 2,tls-server

 *
*/