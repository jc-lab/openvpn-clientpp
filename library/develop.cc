#include <iostream>

#include <uvw/loop.h>

#include <ovpnc/client.h>
#include <ovpnc/vpn_config.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

int main() {
  auto logger = ovpnc::createDefaultLogger([](auto &line) -> void {
    std::cout << line << std::endl;
  });

  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
  ERR_load_ERR_strings();

  auto loop = uvw::Loop::create();
  auto client = ovpnc::Client::create(loop, logger);
  ovpnc::VPNConfig config;
  config.protocol = ovpnc::kTransportTcp;
  config.remote_host = "192.168.1.212"; // 44.167
  config.remote_port = 61194;
//  config.remote_port = 61195;
  client->setAutoReconnect(true);
  client->connect(config);

//  auto ossl_tls_layer = createOpenSslTlsLayer();
//  ossl_tls_layer->setCustomizer();
//  client->setTlsLayer(ossl_tls_layer);

  loop->run();

  return 0;
}
