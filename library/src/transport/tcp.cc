/**
 * @file	tcp.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-08
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "tcp.h"

namespace ovpnc {

TransportTCP::TransportTCP(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<Logger> logger) :
    logger_(logger),
    cleanup_(false),
    connect_handler_(nullptr),
    close_handler_(nullptr),
    error_handler_(nullptr),
    cleanup_handler_(nullptr) {
  logger_->logf(Logger::kLogDebug, "TransportTCP: Construct");

  protocol_config_.is_tcp = true;
  protocol_config_.is_tls = true;

  recv_buffer_.resize(65536);
  recv_position_ = 0;

  handle_ = loop->resource<uvw::TCPHandle>();
  handle_->once<uvw::ConnectEvent>([](auto &event, auto &handle) -> void {
    std::shared_ptr<TransportTCP> self(handle.template data<TransportTCP>());
    if (self->connect_handler_) {
      self->connect_handler_(self.get());
    }
  });
  handle_->once<uvw::EndEvent>([](auto &event, auto &handle) -> void {
    std::shared_ptr<TransportTCP> self(handle.template data<TransportTCP>());
    self->close();
  });
  handle_->once<uvw::CloseEvent>([](auto &event, auto &handle) -> void {
    std::shared_ptr<TransportTCP> self(handle.template data<TransportTCP>());
    if (self->close_handler_) {
      self->close_handler_(self.get());
    }
    self->cleanup();
  });
  handle_->once<uvw::ErrorEvent>([](auto &event, auto &handle) -> void {
    std::shared_ptr<TransportTCP> self(handle.template data<TransportTCP>());
    if (self->error_handler_) {
      self->error_handler_(self.get(), event);
    }
    self->error_handler_ = nullptr;
    self->close();
  });
}

TransportTCP::~TransportTCP() {
  logger_->logf(Logger::kLogDebug, "TransportTCP: Deconstruct");
}

std::shared_ptr<uvw::Loop> TransportTCP::getLoop() {
  return handle_->loop().shared_from_this();
}

void TransportTCP::connect(const sockaddr *addr) {
  handle_->connect(*addr);
}

void TransportTCP::connect(const uvw::Addr &addr) {
  handle_->connect(addr);
}

void TransportTCP::read() {
  handle_->read();
}

void TransportTCP::write(std::unique_ptr<char[]> data, unsigned int len) {
  handle_->write(std::move(data), len);
}

void TransportTCP::onceConnectEvent(const ConnectEventHandler_t &handler) {
  connect_handler_ = handler;
}

void TransportTCP::onDataEvent(const Transport::DataEventHandler_t &handler) {
  handle_->on<uvw::DataEvent>([handler](auto &uvw_event, auto &handle) -> void {
    std::shared_ptr<TransportTCP> self(handle.template data<TransportTCP>());
    DataEvent event;
    event.data = std::move(uvw_event.data);
    event.length = uvw_event.length;
    event.partial = false;
    handler(self.get(), event);
  });
}

void TransportTCP::onceCloseEvent(const Transport::CloseEventHandler_t &handler) {
  close_handler_ = handler;
}

void TransportTCP::onceErrorEvent(const ErrorEventHandler_t &handler) {
  error_handler_ = handler;
}

void TransportTCP::onceCleanupEvent(const CleanupHandler_t &handler) {
  cleanup_handler_ = handler;
}

void TransportTCP::shutdown() {
  handle_->shutdown();
}

void TransportTCP::close() {
//  cleanup();
  handle_->close();
}

std::shared_ptr<TransportTCP> TransportTCP::create(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<Logger> logger) {
  std::shared_ptr<TransportTCP> instance(new TransportTCP(loop, logger));
  instance->self_ = instance;
  instance->handle_->data(instance);
  return std::move(instance);
}

void TransportTCP::cleanup() {
  std::shared_ptr<TransportTCP> self(self_.lock()); // Keep reference

  if (cleanup_) return;
  cleanup_ = true;
  error_handler_ = nullptr;
  if (cleanup_handler_) {
    cleanup_handler_(this);
  }
  cleanup_handler_ = nullptr;
  handle_->data(nullptr);
}

} // namespace ovpnc
