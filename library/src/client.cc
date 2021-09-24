/**
 * @file	client.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <assert.h>

#include <utility>
#include <sstream>

#include <openssl/rand.h>

#include "client.h"
#include "crypto/default_provider.h"
#include "protocol/reliable.h"
#include "protocol/control.h"

using namespace ::jcu::unio;

namespace ovpnc {

std::shared_ptr<Client> ClientImpl::create(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger
) {
  std::shared_ptr<ClientImpl> instance(new ClientImpl(loop, logger));
  instance->self_ = instance;
  instance->init();
  return instance;
}

std::shared_ptr<Client> Client::create(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger
) {
  return ClientImpl::create(std::move(loop), std::move(logger));
}

ClientImpl::ClientImpl(std::shared_ptr<jcu::unio::Loop> loop, std::shared_ptr<jcu::unio::Logger> logger) :
    loop_(loop),
    logger_(logger),
    auto_reconnect_(false) {
  logger_->logf(jcu::unio::Logger::kLogDebug, "Client: Construct");
}

ClientImpl::~ClientImpl() {
  logger_->logf(jcu::unio::Logger::kLogDebug, "Client: Deconstruct");
}

std::shared_ptr<Client> ClientImpl::shared() const {
  return self_.lock();
}

void ClientImpl::init() {
  reliable_ = transport::ReliableLayer::create(
      loop_,
      logger_
  );
  multiplexer_ = transport::Multiplexer::create(
      loop_,
      logger_,
      self_.lock(),
      reliable_
  );
}

void ClientImpl::setAutoReconnect(bool auto_reconnect) {
  auto_reconnect_ = auto_reconnect;
}

bool ClientImpl::connect(const VPNConfig &vpn_config) {
  vpn_config_ = vpn_config;
  return connectImpl();
}

bool ClientImpl::connectImpl() {
  std::shared_ptr<ClientImpl> self(self_.lock());

  if (!vpn_config_.crypto_provider) {
    vpn_config_.crypto_provider.reset(new crypto::DefaultProvider());
  }

  reliable_->start(vpn_config_);
  multiplexer_->start(vpn_config_);

  int mtu = 1400;
  multiplexer_->init(mtu);

  multiplexer_->connect([](jcu::unio::SocketConnectEvent &event, jcu::unio::Resource &handle) -> void {
    fprintf(stderr, "multiplexer->connect ok\n");
  });

  return true;
}

void ClientImpl::read(
    std::shared_ptr<Buffer> buffer,
    CompletionManyCallback<SocketReadEvent> callback
) {
  std::shared_ptr<ClientImpl> self(self_.lock());
  multiplexer_->read(std::move(buffer),
                     [self, callback = std::move(callback)](auto &event, auto &resource) mutable -> void {
                       callback(event, *self);
                     });
}

void ClientImpl::cancelRead() {
  multiplexer_->cancelRead();
}

void ClientImpl::write(
    std::shared_ptr<Buffer> buffer,
    CompletionOnceCallback<SocketWriteEvent> callback
) {
  std::shared_ptr<ClientImpl> self(self_.lock());
  if (!multiplexer_->isHandshaked()) {
    SocketWriteEvent event{UvErrorEvent{UV_ENOTCONN, 0}};
    callback(event, *self);
    return;
  }
  multiplexer_->write(
      std::move(buffer),
      [self, callback = std::move(callback)](auto &event, auto &resource) mutable -> void {
        callback(event, *self);
      });
}

void ClientImpl::connect(
    std::shared_ptr<ConnectParam> connect_param,
    CompletionOnceCallback<SocketConnectEvent> callback
) {
  // DO NOT USE IT
  SocketConnectEvent event{UvErrorEvent{UV_ENOTSUP, 0}};
  callback(event, *this);
}

void ClientImpl::disconnect(
    CompletionOnceCallback<SocketDisconnectEvent> callback
) {
}
bool ClientImpl::isConnected() const {
  if (!multiplexer_) return false;
  return multiplexer_->isConnected();
}
bool ClientImpl::isHandshaked() const {
  if (!multiplexer_) return false;
  return multiplexer_->isHandshaked();
}
void ClientImpl::close() {
  if (multiplexer_) {
    multiplexer_->close();
  }
}

void ClientImpl::onPushReply(std::function<void(const PushOptions& options)> callback) {
  assert(reliable_.get());
  reliable_->onPushReply(std::move(callback));
}

} // namespace ovpnc
