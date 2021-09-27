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
    const jcu::unio::BasicParams& basic_params
) {
  std::shared_ptr<ClientImpl> instance(new ClientImpl(basic_params));
  instance->self_ = instance;
  instance->init();
  return instance;
}

std::shared_ptr<Client> Client::create(
    const jcu::unio::BasicParams& basic_params
) {
  return ClientImpl::create(basic_params);
}

ClientImpl::ClientImpl(const jcu::unio::BasicParams& basic_params) :
    basic_params_(basic_params),
    auto_reconnect_(false) {
  basic_params.logger->logf(jcu::unio::Logger::kLogDebug, "Client: Construct");
}

ClientImpl::~ClientImpl() {
  basic_params_.logger->logf(jcu::unio::Logger::kLogDebug, "Client: Deconstruct");
}

std::shared_ptr<Client> ClientImpl::shared() const {
  return self_.lock();
}

void ClientImpl::_init() {
  reliable_ = transport::ReliableLayer::create(
      basic_params_
  );
  multiplexer_ = transport::Multiplexer::create(
      basic_params_,
      self_.lock(),
      reliable_
  );
  std::shared_ptr<ClientImpl> self(self_.lock());
  multiplexer_->on<jcu::unio::SocketReadEvent>([self](auto& event, auto& resource) -> void {
    self->emit(event);
  });

  jcu::unio::InitEvent event;
  emitInit(std::move(event));
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

  multiplexer_->connect([self](jcu::unio::SocketConnectEvent &event, jcu::unio::Resource &handle) -> void {
    self->emit(event);
  });

  return true;
}

void ClientImpl::read(
    std::shared_ptr<Buffer> buffer
) {
  multiplexer_->read(std::move(buffer));
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
    SocketWriteEvent event { UvErrorEvent::createIfNeeded(UV_ENOTCONN) };
    if (callback) {
      callback(event, *self);
    } else {
      if (event.hasError()) emit(event.error());
      else emit(event);
    }
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
  SocketConnectEvent event { UvErrorEvent::createIfNeeded(UV_ENOTSUP) };
  if (callback) {
    callback(event, *this);
  } else {
    if (event.hasError()) emit(event.error());
    else emit(event);
  }
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

int ClientImpl::bind(std::shared_ptr<BindParam> bind_param) {
  return UV__EINVAL;
}

int ClientImpl::listen(int backlog) {
  return UV__EINVAL;
}

int ClientImpl::accept(std::shared_ptr<StreamSocket> client) {
  return UV__EINVAL;
}

} // namespace ovpnc
