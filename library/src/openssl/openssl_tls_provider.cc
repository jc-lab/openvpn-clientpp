/**
 * @file	openssl_tls_provider.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-13
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <ovpnc/openssl_tls_provider.h>

#include "openssl_tls_layer.h"

namespace ovpnc {
namespace openssl {

class OpenSslTlsProviderImpl : public OpenSslTlsProvider {
 private:
  NewSslCtxHandler_t new_ssl_ctx_handler_;

 public:
  void setNewSslCtxHandler(const NewSslCtxHandler_t &handler) {
    new_ssl_ctx_handler_ = handler;
  }

  std::shared_ptr<transport::TlsLayer> createLayer(
      TlsCreateLayerParams *param
  ) const override {
    std::shared_ptr<SSL_CTX> ssl_ctx = new_ssl_ctx_handler_(param);
    return OpenSslTlsLayer::create(
        param->getLogger(),
        param->getParent(),
        ssl_ctx
    );
  }
};

} // namespace openssl

std::shared_ptr<OpenSslTlsProvider> OpenSslTlsProvider::create() {
  return std::shared_ptr<OpenSslTlsProvider>(new openssl::OpenSslTlsProviderImpl());
}

} // namespace ovpnc
