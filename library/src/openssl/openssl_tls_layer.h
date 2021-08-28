/**
 * @file	openssl_tls_layer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_TRANSPORT_OPENSSL_TLS_H_
#define OVPNC_SRC_TRANSPORT_OPENSSL_TLS_H_

#include <memory>
#include <functional>
#include <utility>

#include <ovpnc/openssl_tls_provider.h>

#include "../log.h"
#include "../transport/transport.h"
#include "../transport/tls_layer.h"

namespace ovpnc {
namespace openssl {

struct SSL_Deleter {
  void operator()(SSL *p) {
    SSL_shutdown(p);
    SSL_free(p);
  }
};
struct BIO_NO_Deleter {
  void operator()(BIO *p) {
    // DO NOT RELEASE!
    // Automatically release by SSL_free with SSL_MODE_RELEASE_BUFFERS option
    // SSL_free:
    //   BIO_free_all(s->wbio);
    //   BIO_free_all(s->rbio);
  }
};

class OpenSslTlsLayer : public transport::TlsLayer {
 private:
  std::weak_ptr<OpenSslTlsLayer> self_;

  std::shared_ptr<SSL_CTX> ssl_ctx_;
  std::unique_ptr<SSL, SSL_Deleter> ssl_;

  std::unique_ptr<BIO, BIO_NO_Deleter> ssl_bio_;
  std::unique_ptr<BIO, BIO_NO_Deleter> app_bio_;

  bool tlsErrorEmit(int ssl_rc);

 public:
  OpenSslTlsLayer(
      std::shared_ptr<Logger> logger,
      std::shared_ptr<transport::ReliableLayer> parent,
      std::shared_ptr<SSL_CTX> ssl_ctx
  );
  ~OpenSslTlsLayer();

  static std::shared_ptr<OpenSslTlsLayer> create(
      std::shared_ptr<Logger> logger,
      std::shared_ptr<transport::ReliableLayer> parent,
      std::shared_ptr<SSL_CTX> ssl_ctx
  );

  void tlsReset() override;
  bool tlsOperation(TlsOp op) override;
  void feedInboundCipherText(const unsigned char *raw_payload, int length) override;
  std::shared_ptr<uvw::Loop> getLoop() override;
  void connect(const sockaddr *addr) override;
  void connect(const uvw::Addr &addr) override;
  void read() override;
  void write(std::unique_ptr<char[]> data, unsigned int len) override;
  void shutdown() override;
  void close() override;

  bool tls1Prf(const uint8_t *seed,
               int seed_len,
               const uint8_t *secret,
               int secret_len,
               uint8_t *output,
               int output_len) const override;
};

} // namespace openssl
} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_OPENSSL_TLS_H_

