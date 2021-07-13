/**
 * @file	openssl_tls.h
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

#include "../log.h"
#include "transport.h"

#include "tls_layer.h"

namespace ovpnc {
namespace transport {

class OpenSslTlsLayer : public TlsLayer {
 public:
  typedef std::function<void(void *ssl_ctx)> SslCtxCustomizer_t;

  OpenSslTlsLayer(std::shared_ptr<ReliableLayer> parent, std::shared_ptr<Logger> logger) : TlsLayer(std::move(parent),
                                                                                                    std::move(logger)) {}

  virtual void setSslCtxCustomizer(const SslCtxCustomizer_t &ssl_ctx_customizer) = 0;
};

std::shared_ptr<OpenSslTlsLayer> createOpenSslTlsLayer(
    std::shared_ptr<ReliableLayer> parent,
    std::shared_ptr<Logger> logger
);

} // namespace transport
} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_OPENSSL_TLS_H_

