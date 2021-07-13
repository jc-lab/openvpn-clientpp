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

#include "transport/reliable_layer.h"

namespace ovpnc {

class ClientImpl : public Client {
 private:
  std::weak_ptr<ClientImpl> self_;

  std::shared_ptr<::uvw::Loop> loop_;
  std::shared_ptr<Logger> logger_;

  VPNConfig vpn_config_;
  bool auto_reconnect_;

  std::shared_ptr<ReliableLayer> reliable_layer_;

 public:
  ClientImpl(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger);
  ~ClientImpl() override;
  static std::shared_ptr<Client> create(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger);

  void setAutoReconnect(bool auto_reconnect) override;
  bool connect(const VPNConfig &vpn_config) override;

 private:
  bool connectImpl();
  void doKeyShare();
  std::string generateOptionString(bool remote) const;
};

} // namespace ovpnc

#endif // OVPNC_SRC_CLIENT_H_
