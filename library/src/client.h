/**
 * @file	client.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_CLIENT_H_
#define OVPNC_SRC_CLIENT_H_

#include <uvw/stream.h>
#include <uvw/tcp.h>

#include <ovpnc/client.h>

#include <utility>

#include "transport/reliable_layer.h"

namespace ovpnc {

class ClientTlsCreateLayerParams : public TlsCreateLayerParams {
 private:
  std::weak_ptr<Client> client_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<transport::ReliableLayer> reliable_layer_;

 public:
  ClientTlsCreateLayerParams(
      std::weak_ptr<Client> client,
      std::shared_ptr<Logger> logger,
      std::shared_ptr<transport::ReliableLayer> reliable_layer
  ) :
  client_(std::move(client)),
  logger_(std::move(logger)),
  reliable_layer_(std::move(reliable_layer))
  {}

  bool isServerMode() const override {
    return false;
  }

  std::shared_ptr<Client> getClient() const override {
    return client_.lock();
  }
  std::shared_ptr<Logger> getLogger() const override {
    return logger_;
  }
  std::shared_ptr<transport::ReliableLayer> getParent() const override {
    return reliable_layer_;
  }
};

class ClientImpl : public Client {
 private:
  std::weak_ptr<ClientImpl> self_;

  std::shared_ptr<::uvw::Loop> loop_;
  std::shared_ptr<Logger> logger_;

  VPNConfig vpn_config_;
  bool auto_reconnect_;

  std::shared_ptr<transport::ReliableLayer> reliable_layer_;

 public:
  ClientImpl(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger);
  ~ClientImpl() override;
  static std::shared_ptr<Client> create(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger);

  void setAutoReconnect(bool auto_reconnect) override;
  bool connect(const VPNConfig &vpn_config) override;

 private:
  bool connectImpl();
};

} // namespace ovpnc

#endif // OVPNC_SRC_CLIENT_H_
