/**
 * @file	client.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_CLIENT_H_
#define OVPNC_CLIENT_H_

#include <memory>

#include <jcu-unio/loop.h>
#include <jcu-unio/log.h>
#include <jcu-unio/shared_object.h>
#include <jcu-unio/net/stream_socket.h>

#include "vpn_config.h"
#include "log.h"

namespace ovpnc {

class Client : public jcu::unio::StreamSocket, public jcu::unio::SharedObject<Client> {
 public:
  virtual ~Client() = default;

  static std::shared_ptr<Client> create(std::shared_ptr<jcu::unio::Loop> loop, std::shared_ptr<jcu::unio::Logger> logger);

  virtual void setAutoReconnect(bool auto_reconnect) = 0;
  virtual bool connect(const VPNConfig &vpn_config) = 0;
};

} // namespace ovpnc

#endif //OVPNC_CLIENT_H_
