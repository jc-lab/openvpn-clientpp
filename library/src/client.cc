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

#include "transport/tcp.h"
#include "transport/udp.h"
#include "transport/openssl_tls.h"

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
  std::shared_ptr<ClientImpl> self(self_.lock());
  vpn_config_ = vpn_config;
  return connectImpl();
}

bool ClientImpl::connectImpl() {
  std::shared_ptr<ClientImpl> self(self_.lock());
  std::shared_ptr<Transport> transport;

  if (vpn_config_.protocol == kTransportTcp) {
    transport = TransportTCP::create(loop_, logger_);
  } else if (vpn_config_.protocol == kTransportUdp) {
//    transport = TransportUDP::create(loop_, logger_);
  } else {
    return false;
  }
//
//  transport->onceConnectEvent([self](Transport* transport) -> void {
//    self->logger_->logf(Logger::kLogDebug, "Client: transport connected");
//  });
//  transport->onceCloseEvent([self](Transport* transport) -> void {
//    self->logger_->logf(Logger::kLogDebug, "Client: transport close");
//  });
//  transport->onceErrorEvent([self](Transport* transport, uvw::ErrorEvent& event) -> void {
//    self->auto_reconnect_ = false;
//    self->logger_->logf(Logger::kLogWarn, "Client: transport error[%d]: %d: %s", event.code(), event.name(), event.what());
//  });
//  transport->onceCleanupEvent([self](Transport* transport) -> void {
//    self->logger_->logf(Logger::kLogDebug, "Client: transport cleanup");
//
//    if (self->auto_reconnect_) {
//      std::shared_ptr<uvw::TimerHandle> timer = self->loop_->resource<uvw::TimerHandle>();
//      timer->once<uvw::TimerEvent>([self](auto &event, uvw::TimerHandle &handle) -> void {
//        self->connectImpl();
//        handle.close();
//      });
//      timer->start(std::chrono::milliseconds{1000}, std::chrono::milliseconds{0});
//    }
//
//    self->transport.reset();
//  });
//  transport->onDataEvent([self](Transport* transport, Transport::DataEvent& event) -> void {
//    std::string s(event.data.get(), event.length);
//    self->logger_->logf(Logger::kLogDebug, "Client: transport data event: %s", s.c_str()); // TODO: REMOVE IT!
//    transport->write(std::move(event.data), event.length);
//  });

  reliable_layer_ = ReliableLayer::create(transport, logger_);
  reliable_layer_->data(self_.lock());
  reliable_layer_->onceConnectEvent([](Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: ReliableLayer: handshaked");
    self->doKeyShare();
    //TODO: do 대신 State Machine 으로 변경
  });
  reliable_layer_->onceCloseEvent([](Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: CloseEvent");
  });
  reliable_layer_->onceCleanupEvent([](Transport *transport) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: CleanupEvent");
  });
  reliable_layer_->onceErrorEvent([](Transport *transport, uvw::ErrorEvent &event) -> void {
    std::shared_ptr<ClientImpl> self(transport->template data<ClientImpl>());
    self->logger_->logf(Logger::kLogDebug, "Client: ErrorEvent: %s", event.what());
    transport->close();
  });

  ::uvw::Addr addr{
      vpn_config_.remote_host,
      vpn_config_.remote_port
  };
  transport->connect(addr);

  return true;
}

void ClientImpl::doKeyShare() {
  protocol::control::KeyMethod2 key_method;
  std::unique_ptr<char[]> raw_packet;
  key_method.init(false);
  key_method.setOptionString(generateOptionString(false));
  raw_packet.reset(new char[key_method.getSerializedSize()]);
  key_method.serializeTo((unsigned char *) raw_packet.get());
  logger_->logf(Logger::kLogDebug, "doKeyShare: %s", key_method.optionsString().c_str());
  reliable_layer_->write(std::move(raw_packet), key_method.getSerializedSize());
}

std::string ClientImpl::generateOptionString(bool remote) const {
  std::stringstream option_string;
  option_string << "V4";
  option_string << ",dev-type tun";
  option_string << ",link-mtu 1500";
  option_string << ",tun-mtu 1500";
  if (vpn_config_.protocol == kTransportTcp) {
    option_string << ",proto tcp";
  } else if (vpn_config_.protocol == kTransportUdp) {
    option_string << ",proto udp";
  }
  // keydir 0 : server
  // keydir 1 : client
  option_string << ",cipher AES-256-GCM";
  option_string << ",auth none";
  option_string << ",keysize 0";
//  option_string << ",tls-auth";
  option_string << ",key-method 2";

  if (remote) {
    option_string << ",tls-server";
  } else {
    option_string << ",tls-client";
  }
  return option_string.str();
}

} // namespace ovpnc
