/**
 * @file	client.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#include <utility>
#include <sstream>

#include <openssl/rand.h>

#include <uvw/timer.h>

#include "client.h"
#include "log.h"

#include "crypto/default_provider.h"

#include "transport/tcp.h"
#include "transport/udp.h"

#include "protocol/control.h"

namespace ovpnc {

std::shared_ptr<Client> ClientImpl::create(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger) {
  std::shared_ptr<ClientImpl> instance(new ClientImpl(loop, logger));
  instance->self_ = instance;
  return instance;
}

std::shared_ptr<Client> Client::create(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger) {
  return ClientImpl::create(std::move(loop), std::move(logger));
}

ClientImpl::ClientImpl(std::shared_ptr<::uvw::Loop> loop, std::shared_ptr<Logger> logger) :
    loop_(loop),
    logger_(logger),
    auto_reconnect_(false) {
  if (!logger_) {
    logger_ = intl::createNullLogger();
  }
  logger_->logf(Logger::kLogDebug, "Client: Construct");
}

ClientImpl::~ClientImpl() {
  logger_->logf(Logger::kLogDebug, "Client: Deconstruct");
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
  std::shared_ptr<transport::Transport> transport;

  if (!vpn_config_.crypto_provider) {
    vpn_config_.crypto_provider.reset(new crypto::DefaultProvider());
  }

  if (vpn_config_.protocol == kTransportTcp) {
    transport = transport::TransportTCP::create(loop_, logger_);
  } else if (vpn_config_.protocol == kTransportUdp) {
//    transport = TransportUDP::create(loop_, logger_);
  } else {
    return false;
  }

  reliable_layer_ = transport::ReliableLayer::create(
      logger_,
      transport,
      [weak_client =
      std::weak_ptr<ClientImpl>(self)](std::shared_ptr<transport::ReliableLayer> self) -> std::shared_ptr<transport::TlsLayer> {
        std::shared_ptr<ClientImpl> client(weak_client.lock());
        ClientTlsCreateLayerParams params(
            client,
            client->logger_,
            std::move(self)
        );
        return client->vpn_config_.tls_provider->createLayer(&params);
      },
      vpn_config_.crypto_provider
  );

  reliable_layer_->data(self_.lock());
  reliable_layer_->onceConnectEvent([](transport::Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: ReliableLayer: handshaked");
  });
  reliable_layer_->onceCloseEvent([](transport::Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: CloseEvent");
  });
  reliable_layer_->onceCleanupEvent([](transport::Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    transport->data(nullptr);
    self->logger_->logf(Logger::kLogDebug, "Client: CleanupEvent");
  });
  reliable_layer_->onceErrorEvent([](transport::Transport *transport, uvw::ErrorEvent &event) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: ErrorEvent: %s", event.what());
    transport->close();
  });
  reliable_layer_->onDataEvent([](transport::Transport *transport, transport::Transport::DataEvent &event) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
  });

  ::uvw::Addr addr{
      vpn_config_.remote_host,
      vpn_config_.remote_port
  };
  transport->connect(addr);

  return true;
}

} // namespace ovpnc
