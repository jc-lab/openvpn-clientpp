/**
 * @file	reliable_layer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-10
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <cstring>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "reliable_layer.h"

#include "../protocol/reliable.h"

namespace ovpnc {
namespace transport {

ReliableLayer::ReliableLayer(std::shared_ptr<Transport> transport, std::shared_ptr<Logger> logger) :
    transport_(transport),
    logger_(logger),
    cleanup_(false),
    state_(kUnknownState) {
  logger_->logf(Logger::kLogDebug, "ReliableLayer: Construct");

  recv_buffer_.resize(65536);

  transport_->onceConnectEvent([](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());

    self->logger_->logf(Logger::kLogDebug, "ReliableLayer: transport connected");

    self->sessionInit();
    transport->read();
    self->handshake();
  });
  transport_->onDataEvent([](Transport *transport, Transport::DataEvent &event) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
    self->processInbound(event);
  });
  transport_->onceErrorEvent([](Transport *transport, uvw::ErrorEvent &event) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
    if (self->error_handler_) {
      self->error_handler_(self.get(), event);
    }
    // Should the parent automatically closes when an error occurs.
  });
  transport_->onceCloseEvent([](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
    if (self->close_handler_) {
      self->close_handler_(self.get());
    }
  });
  transport_->onceCleanupEvent([](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
    self->cleanup();
  });
}

ReliableLayer::~ReliableLayer() {
  logger_->logf(Logger::kLogDebug, "ReliableLayer: Deconstruct");
}

std::shared_ptr<ReliableLayer> ReliableLayer::create(std::shared_ptr<Transport> parent,
                                                     std::shared_ptr<Logger> logger) {
  std::shared_ptr<ReliableLayer> instance(new ReliableLayer(parent, logger));
  instance->self_ = instance;
  instance->transport_->data(instance);
  instance->tlsInit();
  return std::move(instance);
}

std::shared_ptr<uvw::Loop> ReliableLayer::getLoop() {
  return transport_->getLoop();
}

void ReliableLayer::connect(const sockaddr *addr) {
  state_ = kUnknownState;
  transport_->connect(addr);
}

void ReliableLayer::connect(const uvw::Addr &addr) {
  state_ = kUnknownState;
  transport_->connect(addr);
}

void ReliableLayer::read() {
  // nothing
}

void ReliableLayer::write(std::unique_ptr<char[]> data, unsigned int len) {
  if (protocol_config_.is_tls) {
    tls_layer_->write(std::move(data), len);
  }
}

void ReliableLayer::onceConnectEvent(const ConnectEventHandler_t &handler) {
  connect_handler_ = handler;
}

void ReliableLayer::onDataEvent(const Transport::DataEventHandler_t &handler) {
  data_handler_ = handler;
}

void ReliableLayer::onceCloseEvent(const Transport::CloseEventHandler_t &handler) {
  close_handler_ = handler;
}

void ReliableLayer::onceErrorEvent(const ErrorEventHandler_t &handler) {
  error_handler_ = handler;
}

void ReliableLayer::onceCleanupEvent(const CleanupHandler_t &handler) {
  cleanup_handler_ = handler;
}

void ReliableLayer::shutdown() {
  transport_->shutdown();
}

void ReliableLayer::close() {
  transport_->close();
}

void ReliableLayer::cleanup() {
  std::shared_ptr<ReliableLayer> self(self_.lock()); // Keep reference

  if (cleanup_) return;
  cleanup_ = true;
  error_handler_ = nullptr;
  if (cleanup_handler_) {
    cleanup_handler_(this);
  }
  cleanup_handler_ = nullptr;
  transport_->data(nullptr);
}

static unsigned readUint16FromPacket(const unsigned char *ptr) {
  unsigned int x = ((unsigned int) ptr[0]) << 8;
  x |= ((unsigned int) ptr[1]);
  return x;
}

void ReliableLayer::sessionInit() {
  recv_position_ = 0;
  local_packet_id_ = 0;
  peer_packet_id_ = 0;
  RAND_bytes(session_id_, sizeof(session_id_));
  std::memset(peer_session_id_, 0, sizeof(peer_session_id_));
}

void ReliableLayer::handshake() {
  protocol::reliable::ControlV1Payload control_payload{protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V2};
  control_payload.setSessionId(session_id_);
  control_payload.setAckPacketIdArrayLength(0);
  control_payload.setPacketId(local_packet_id_++);

  logger_->logf(Logger::kLogDebug, "ReliableLayer: start handshake");

  state_ = kReliableHandshakingState;
  sendSimplePayload(&control_payload);
}

void ReliableLayer::processInbound(Transport::DataEvent &event) {
  unsigned char *recv_buffer_ptr = recv_buffer_.data();
  int offset = 0;

  logger_->logf(Logger::kLogDebug, "processData: %d", event.length);

  do {
    int recv_available = event.length - offset;
    int packet_length = 2;
    if (recv_position_ >= 2) {
      packet_length = 2 + readUint16FromPacket(recv_buffer_ptr);
      if (packet_length == recv_position_) {
        logger_->logf(Logger::kLogDebug, "a packet: %d", packet_length);
        processPacketInbound(recv_buffer_ptr, packet_length);
        recv_position_ = 0;
        packet_length = 2;
      }
    }
    if (event.length == offset) {
      break;
    }
    int packet_remaining = packet_length - recv_position_;
    int copy_length = (packet_remaining > recv_available) ? recv_available : packet_remaining;
    // assert (copy_length > 0);

    std::memcpy(recv_buffer_ptr + recv_position_, event.data.get() + offset, copy_length);
    recv_position_ += copy_length;
    offset += copy_length;
  } while (true);
}

void ReliableLayer::processPacketInbound(const unsigned char *buffer, int length) {
  auto config = transport_->getProtocolConfig();
  const unsigned char *p = buffer;
  const unsigned char *end = buffer + length;
  uint8_t op_code;
  uint8_t key_id;
  if (config->is_tcp) {
    p += 2;
  } else {
    logger_->logf(Logger::kLogError, "ReliableLayer: non-tcp not supported yet");
    return;
  }

  if (config->is_tls) {
    op_code = (*p >> 3) & 0x1f;
    key_id = *p & 0x7;
    p++;
  } else {
    logger_->logf(Logger::kLogError, "ReliableLayer: non-tls not supported yet");
    return;
  }

  logger_->logf(Logger::kLogDebug,
                "ReliableLayer: processPacketInbound: op_code=%u, key_id=%u, size=%d",
                op_code,
                key_id,
                length);
  switch (op_code) {
    case protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2:
      processControlHardResetServerV2((protocol::reliable::OpCode) op_code,
                                      p,
                                      end - p);
      break;
    case protocol::reliable::P_CONTROL_V1:processControlV1((protocol::reliable::OpCode) op_code, p, end - p);
      break;
    default:
      logger_->logf(Logger::kLogDebug,
                    "ReliableLayer: processPacketInbound: op_code=%u: Not supported yet",
                    op_code);
  }
}

void ReliableLayer::processControlHardResetServerV2(protocol::reliable::OpCode op_code,
                                                    const unsigned char *raw_payload,
                                                    int length) {
  protocol::reliable::ControlV1Payload control_payload{op_code};
  int proceed_length = control_payload.deserializeFrom(raw_payload, length);
  if (proceed_length < 0) {
    logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: deserialize failed");
    return;
  }

  // Check ACK
  if (control_payload.hasRemoteSessionId()) {
    if (std::memcmp(session_id_, control_payload.remoteSessionId(), sizeof(session_id_)) != 0) {
      logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: invalid session id");
      return;
    }
//    logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: not supported case#01");
//    return ;
  }

  std::memcpy(peer_session_id_, control_payload.sessionId(), sizeof(peer_session_id_));

  uint32_t ack_packet_ids[1] = {
      control_payload.packetId()
  };
  sendAckV1(1, ack_packet_ids);

  if (protocol_config_.is_tls) {
    tls_layer_->tlsReset();
    tls_layer_->tlsOperation(TlsLayer::kTlsOpHandshake);
  } else {
    postHandshaked();
  }
}

//TODO: 패킷 합쳐서 보내기 (Ack를 Control패킷에)

void ReliableLayer::processControlV1(protocol::reliable::OpCode op_code, const unsigned char *raw_payload, int length) {
  protocol::reliable::ControlV1Payload control_payload{op_code};
  int offset = control_payload.deserializeFrom(raw_payload, length);
  if (offset < 0) {
    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: deserialize failed");
    return;
  }
  if (control_payload.hasRemoteSessionId()) {
//  if (!control_payload.hasRemoteSessionId()) {
//    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: not supported case#01");
//    return ;
//  }
    if (std::memcmp(session_id_, control_payload.remoteSessionId(), sizeof(session_id_))) {
      logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: invalid session id");
      return;
    }
  }
  if (std::memcmp(peer_session_id_, control_payload.sessionId(), sizeof(peer_session_id_)) != 0) {
    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: invalid peer's session id");
    return;
  }

  if (protocol_config_.is_tls) {
    tls_layer_->feedInboundCipherText(raw_payload + offset, length - offset);
  }

  uint32_t ack_packet_ids[1] = {
      control_payload.packetId()
  };
  sendAckV1(1, ack_packet_ids);
}

void ReliableLayer::initControlV1PayloadToSend(protocol::reliable::ControlV1Payload *payload) {
  payload->setSessionId(session_id_);
  payload->setRemoteSessionId(peer_session_id_);
  payload->setPacketId(local_packet_id_++);
}

void ReliableLayer::initAckV1PayloadToSend(protocol::reliable::AckV1Payload *payload) {
  payload->setSessionId(session_id_);
  payload->setRemoteSessionId(peer_session_id_);
}

void ReliableLayer::sendSimplePayload(const protocol::reliable::ReliablePayload *payload) {
  protocol::reliable::UniqueCharArrPacketWriter packet_writer{transport_->getProtocolConfig()};
  packet_writer.prepare(payload, 0);
  packet_writer.write(0);
  transport_->write(std::move(packet_writer.buffer), packet_writer.getPacketLength());
}

// TLS

void ReliableLayer::tlsInit() {
  std::weak_ptr<ReliableLayer> weak_self(self_);
  auto openssl_tls_layer = createOpenSslTlsLayer(weak_self.lock(), logger_);
  openssl_tls_layer->setSslCtxCustomizer([](void *p_ssl_ctx) -> void {
    SSL_CTX *ssl_ctx = (SSL_CTX *) p_ssl_ctx;
    SSL_CTX_use_PrivateKey_file(ssl_ctx, "D:\\jcworkspace\\openvpn-cpp\\test\\client.key", SSL_FILETYPE_PEM);
    SSL_CTX_use_certificate_file(ssl_ctx, "D:\\jcworkspace\\openvpn-cpp\\test\\client.pem", SSL_FILETYPE_PEM);
  });
  tls_layer_ = openssl_tls_layer;
  tls_layer_->onceConnectEvent([weak_self](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(weak_self.lock());
    self->postHandshaked();
  });
  tls_layer_->onceErrorEvent([weak_self](Transport *transport, uvw::ErrorEvent &event) -> void {
    std::shared_ptr<ReliableLayer> self(weak_self.lock());
    if (self->error_handler_) {
      self->error_handler_(self.get(), event);
    }
    // Should the parent automatically closes when an error occurs.
  });
  tls_layer_->onceCloseEvent([weak_self](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(weak_self.lock());
    self->close();
  });
  tls_layer_->tlsInit();
}

void ReliableLayer::postHandshaked() {
  state_ = kEstablishedState;
  logger_->logf(Logger::kLogDebug, "OpenSslTls: handshaked");
  if (connect_handler_) {
    connect_handler_(this);
  }
}

void ReliableLayer::sendAckV1(int packet_id_count, uint32_t *packet_ids) {
  protocol::reliable::AckV1Payload ack_payload{protocol::reliable::P_ACK_V1};
  ack_payload.setAckPacketIdArrayLength(packet_id_count);
  for (int i = 0; i < packet_id_count; i++) {
    ack_payload.ackPacketIdArray()[i] = packet_ids[i];
  }
  initAckV1PayloadToSend(&ack_payload);
  sendSimplePayload(&ack_payload);
}

void ReliableLayer::writeRawPacket(std::unique_ptr<char[]> data, unsigned int len) {
  transport_->write(std::move(data), len);
}

} // namespace transport
} // namespace ovpnc

