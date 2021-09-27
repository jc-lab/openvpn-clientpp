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

  jcu::unio::BasicParams basic_params_;

  VPNConfig vpn_config_;
  bool auto_reconnect_;

  std::shared_ptr<transport::ReliableLayer> reliable_;
  std::shared_ptr<transport::Multiplexer> multiplexer_;

 protected:
  void _init() override;

 public:
  ClientImpl(const jcu::unio::BasicParams& basic_params);
  ~ClientImpl() override;
  static std::shared_ptr<Client> create(
      const jcu::unio::BasicParams& basic_params
  );

  void setAutoReconnect(bool auto_reconnect) override;
  bool connect(const VPNConfig &vpn_config) override;

  std::shared_ptr<Client> shared() const override;
  void close() override;

  void read(
      std::shared_ptr<jcu::unio::Buffer> buffer
  ) override;
  void cancelRead() override;
  void write(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback = nullptr
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

  int bind(std::shared_ptr<jcu::unio::BindParam> bind_param) override;
  int listen(int backlog) override;
  int accept(std::shared_ptr<StreamSocket> client) override;

 public:
  bool isConnected() const override;
  bool isHandshaked() const override;

  void onPushReply(std::function<void(const PushOptions& options)> callback) override;

 private:
  bool connectImpl();
};

} // namespace ovpnc

#endif // OVPNC_SRC_CLIENT_H_
