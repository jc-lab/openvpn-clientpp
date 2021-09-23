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

#include <jcu-unio/net/tcp_socket.h>
#include <jcu-unio/net/ssl_context.h>
#include <jcu-unio/net/ssl_socket.h>

#include <ovpnc/client.h>
#include <ovpnc/push_options.h>

#include <utility>

#include "transport/multiplexer.h"
#include "transport/reliable_layer.h"

namespace ovpnc {

class ClientImpl : public Client {
 private:
  std::weak_ptr<ClientImpl> self_;

  std::shared_ptr<jcu::unio::Loop> loop_;
  std::shared_ptr<jcu::unio::Logger> logger_;

  VPNConfig vpn_config_;
  bool auto_reconnect_;

  std::shared_ptr<transport::ReliableLayer> reliable_;
  std::shared_ptr<transport::Multiplexer> multiplexer_;

  void init();

 public:
  ClientImpl(std::shared_ptr<jcu::unio::Loop> loop, std::shared_ptr<jcu::unio::Logger> logger);
  ~ClientImpl() override;
  static std::shared_ptr<Client> create(
      std::shared_ptr<jcu::unio::Loop> loop,
      std::shared_ptr<jcu::unio::Logger> logger
  );

  void setAutoReconnect(bool auto_reconnect) override;
  bool connect(const VPNConfig &vpn_config) override;

  std::shared_ptr<Client> shared() const override;
  void close() override;

  void read(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionManyCallback<jcu::unio::SocketReadEvent> callback
  ) override;
  void cancelRead() override;
  void write(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
  ) override;

  /**
   * DO NOT USE IT
   * @param connect_param
   * @param callback
   */
  void connect(
      std::shared_ptr<jcu::unio::ConnectParam> connect_param,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketConnectEvent> callback
  ) override;
  void disconnect(
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketDisconnectEvent> callback
  ) override;
  bool isConnected() const override;
  bool isHandshaked() const override;

  void onPushReply(std::function<void(const std::string& options)> callback) override;

 private:
  bool connectImpl();
};

} // namespace ovpnc

#endif // OVPNC_SRC_CLIENT_H_
