/**
 * @file	tls_layer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-13
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_TRANSPORT_TLS_LAYER_H_
#define OVPNC_SRC_TRANSPORT_TLS_LAYER_H_

#include <memory>
#include <vector>

#include "../log.h"
#include "transport.h"

namespace ovpnc {

class ReliableLayer;

class TlsLayer : public Transport {
 public:
  enum State {
    kIdleState = 0,
    kHandshakeState,
    kEstablishedState,
    kHandshakeFailedState
  };

  enum TlsOp {
    kTlsOpHandshake,
    kTlsOpWriteToRemote,
    kTlsOpReadFromRemote
  };

 protected:
  std::shared_ptr<Logger> logger_;
  std::weak_ptr<ReliableLayer> parent_;

  bool cleanup_;
  State state_;

  ConnectEventHandler_t connect_handler_;
  CloseEventHandler_t close_handler_;
  ErrorEventHandler_t error_handler_;
  CleanupHandler_t cleanup_handler_;
  DataEventHandler_t data_handler_;

  TlsLayer(std::shared_ptr<ReliableLayer> parent, std::shared_ptr<Logger> logger) :
      parent_(parent),
      logger_(logger),
      cleanup_(false),
      state_(kIdleState) {}

 public:
  void onceConnectEvent(const ConnectEventHandler_t &handler) {
    connect_handler_ = handler;
  }

  void onDataEvent(const Transport::DataEventHandler_t &handler) {
    data_handler_ = handler;
  }

  void onceCloseEvent(const Transport::CloseEventHandler_t &handler) {
    close_handler_ = handler;
  }

  void onceErrorEvent(const ErrorEventHandler_t &handler) {
    error_handler_ = handler;
  }

  void onceCleanupEvent(const CleanupHandler_t &handler) {
    cleanup_handler_ = handler;
  }

  virtual void tlsInit() = 0;
  virtual void tlsReset() = 0;
  virtual bool tlsOperation(TlsOp op) = 0;

  virtual void feedInboundCipherText(const unsigned char *raw_payload, int length) = 0;

  void postHandshaked() {
    if (connect_handler_) {
      connect_handler_(this);
    }
  }
};

} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_TLS_LAYER_H_
