/**
 * @file	openssl_tls_provider.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-13
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_OPENSSL_TLS_PROVIDER_H_
#define OVPNC_OPENSSL_TLS_PROVIDER_H_

#include <functional>

#include <openssl/ssl.h>

#include "tls_provider.h"

namespace ovpnc {

class Client;

class OpenSslTlsProvider : public TlsProvider {
 public:
  typedef std::function<std::shared_ptr<SSL_CTX>(TlsCreateLayerParams *param)> NewSslCtxHandler_t;
  virtual void setNewSslCtxHandler(const NewSslCtxHandler_t& handler) = 0;
  static std::shared_ptr<OpenSslTlsProvider> create();
};

} // namespace ovpnc

#endif //OVPNC_OPENSSL_TLS_PROVIDER_H_
