/**
 * @file	tls_provider.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-13
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_TLS_PROVIDER_H_
#define OVPNC_TLS_PROVIDER_H_

#include <memory>

#include <stdint.h>

namespace ovpnc {

class Logger;
class Client;

namespace transport {

class TlsLayer;
class ReliableLayer;

} // namespace transport

class TlsCreateLayerParams {
 public:
  virtual ~TlsCreateLayerParams() = default;
  virtual bool isServerMode() const = 0;
  virtual std::shared_ptr<Client> getClient() const = 0;
  virtual std::shared_ptr<Logger> getLogger() const = 0;
  virtual std::shared_ptr<transport::ReliableLayer> getParent() const = 0;
};

class TlsProvider {
 public:
  virtual ~TlsProvider() = default;
  virtual std::shared_ptr<transport::TlsLayer> createLayer(
      TlsCreateLayerParams *param
  ) const = 0;
};

} // namespace ovpnc

#endif //OVPNC_TLS_PROVIDER_H_
