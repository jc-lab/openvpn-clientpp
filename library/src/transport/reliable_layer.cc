/**
 * @file	reliable_layer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-10
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <cstring>
#include <utility>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <ovpnc/tls_provider.h>

#include "reliable_layer.h"

#include "../protocol/reliable.h"
#include "../protocol/control.h"

#define KEY_EXPANSION_ID "OpenVPN"

namespace ovpnc {
namespace transport {

static void dump(const void* ptr, int length) {
  const unsigned char* c = (const unsigned char*)ptr;
  for (int i=0; i<length; i++) {
    printf("%02x ", c[i]);
  }
  printf("\n");
}


ReliableLayer::ReliableLayer(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Transport> transport,
    ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
    std::shared_ptr<crypto::Provider> crypto_provider
) :
    logger_(std::move(logger)),
    transport_(std::move(transport)),
    tls_layer_supplier_(std::move(tls_layer_supplier)),
    crypto_provider_(std::move(crypto_provider)),
    cleanup_(false),
    state_(kNotStarted) {
  logger_->logf(Logger::kLogDebug, "ReliableLayer: Construct");

  recv_buffer_.resize(65536);

  transport_->onceConnectEvent([](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());

    self->logger_->logf(Logger::kLogDebug, "ReliableLayer: transport connected");

    self->sessionInit();
    transport->read();

    self->state_ = kInitialState;
    self->sessionProcess();
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

std::shared_ptr<ReliableLayer> ReliableLayer::create(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Transport> parent,
    ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
    std::shared_ptr<crypto::Provider> crypto_provider
    ) {
  std::shared_ptr<ReliableLayer> instance(new ReliableLayer(
      std::move(logger),
      std::move(parent),
      std::move(tls_layer_supplier),
      crypto_provider
  ));
  instance->self_ = instance;
  instance->transport_->data(instance);
  instance->tlsInit();
  return std::move(instance);
}

std::shared_ptr<uvw::Loop> ReliableLayer::getLoop() {
  return transport_->getLoop();
}

void ReliableLayer::connect(const sockaddr *addr) {
  state_ = kNotStarted;
  transport_->connect(addr);
}

void ReliableLayer::connect(const uvw::Addr &addr) {
  state_ = kNotStarted;
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
  client_packet_id_ = 0;
  server_packet_id_ = 0;
  RAND_bytes(client_session_id_, sizeof(client_session_id_));
  std::memset(server_session_id_, 0, sizeof(server_session_id_));
}

void ReliableLayer::sendControlHardResetClientV2() {
  protocol::reliable::ControlV1Payload control_payload{protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V2};
  control_payload.setSessionId(client_session_id_);
  control_payload.setAckPacketIdArrayLength(0);
  control_payload.setPacketId(client_packet_id_++);

  logger_->logf(Logger::kLogDebug, "ReliableLayer: sendControlHardResetClientV2");

  state_ = kPreStartState;
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
  const unsigned char* op_begin = nullptr;
  uint8_t op_code;
  uint8_t key_id;
  if (config->is_tcp) {
    p += 2;
  } else {
    logger_->logf(Logger::kLogError, "ReliableLayer: non-tcp not supported yet");
    return;
  }

  op_begin = p;
  if (config->is_tls) {
    op_code = (*p >> 3) & 0x1f;
    key_id = *p & 0x7;
    p++;
  } else {
    logger_->logf(Logger::kLogError, "ReliableLayer: non-tls not supported yet");
    return;
  }

  logger_->logf(
      Logger::kLogDebug,
      "ReliableLayer: processPacketInbound: op_code=%u, key_id=%u, size=%d",
      op_code,
      key_id,
      length
  );

  switch (op_code) {
    case protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2:
      processControlHardResetServerV2(
          (protocol::reliable::OpCode) op_code,
          p,
          end - p
      );
      break;
    case protocol::reliable::P_CONTROL_V1:
      processControlV1((protocol::reliable::OpCode) op_code, p, end - p);
      break;
    case protocol::reliable::P_DATA_V1:
    case protocol::reliable::P_DATA_V2:
      processData((protocol::reliable::OpCode) op_code, op_begin, p, end - p);
      break;
    default:
      logger_->logf(
          Logger::kLogDebug,
          "ReliableLayer: processPacketInbound: op_code=%u: Not supported yet",
          op_code
      );
  }
}

void ReliableLayer::processControlHardResetServerV2(
    protocol::reliable::OpCode op_code,
    const unsigned char *raw_payload,
    int length
) {
  protocol::reliable::ControlV1Payload control_payload{op_code};
  int proceed_length = control_payload.deserializeFrom(raw_payload, length);
  if (proceed_length < 0) {
    logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: deserialize failed");
    return;
  }

  // Check ACK
  if (control_payload.hasRemoteSessionId()) {
    if (std::memcmp(client_session_id_, control_payload.remoteSessionId(), sizeof(client_session_id_)) != 0) {
      logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: invalid session id");
      return;
    }
  }

  std::memcpy(server_session_id_, control_payload.sessionId(), sizeof(server_session_id_));

  uint32_t ack_packet_ids[1] = {
      control_payload.packetId()
  };
  sendAckV1(1, ack_packet_ids);

  if (protocol_config_.is_tls) {
    tls_layer_->tlsReset();
    tls_layer_->tlsOperation(TlsLayer::kTlsOpHandshake);
  } else {
    state_ = kStartState;
    sessionProcess();
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
    if (std::memcmp(client_session_id_, control_payload.remoteSessionId(), sizeof(client_session_id_))) {
      logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: invalid session id");
      return;
    }
  }
  if (std::memcmp(server_session_id_, control_payload.sessionId(), sizeof(server_session_id_)) != 0) {
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
  payload->setSessionId(client_session_id_);
  payload->setRemoteSessionId(server_session_id_);
  payload->setPacketId(client_packet_id_++);
}

void ReliableLayer::initAckV1PayloadToSend(protocol::reliable::AckV1Payload *payload) {
  payload->setSessionId(client_session_id_);
  payload->setRemoteSessionId(server_session_id_);
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
  tls_layer_ = tls_layer_supplier_(weak_self.lock());
  tls_layer_->onceConnectEvent([weak_self](Transport *transport) -> void {
    std::shared_ptr<ReliableLayer> self(weak_self.lock());
    self->state_ = kStartState;
    self->sessionProcess();
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
  tls_layer_->onDataEvent([weak_self](Transport* transport, DataEvent& event) -> void {
    std::shared_ptr<ReliableLayer> self(weak_self.lock());
    self->processInboundKeyMethod(event.data.get(), event.length);
  });
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

void ReliableLayer::processData(protocol::reliable::OpCode op_code, const unsigned char *op_begin, const unsigned char *raw_payload, int length) {
  const unsigned char *p = raw_payload;
  const unsigned char *end = raw_payload + length;
  bool no_iv = false;
  auto& crypto_ctx = data_crypto_.inbound;
  const unsigned char* ad_start;
  uint32_t packet_id = 0;
  const unsigned char* tag_ptr = nullptr;
  int rc;

  dump(p, end - p);

  if (op_code == protocol::reliable::P_DATA_V2)
  {
    ad_start = op_begin;
    p += 3;
  } else if (op_code == protocol::reliable::P_DATA_V1) {
    ad_start = raw_payload;
  }

  /* Combine IV from explicit part from packet and implicit part from context */
  {
    uint8_t iv[EVP_MAX_IV_LENGTH] = { 0 };
    const int iv_len = crypto_ctx.cipher->getIVSize();
    const size_t packet_iv_len = iv_len - crypto_ctx.implicit_iv.size();
    memcpy(iv, p, packet_iv_len);
    memcpy(iv + packet_iv_len, crypto_ctx.implicit_iv.data(), crypto_ctx.implicit_iv.size());
    printf("DECRYPT IV : ");
    dump(iv, iv_len);
    crypto_ctx.cipher->reset(iv);
  }

  packet_id = protocol::reliable::deserializeUint32(p);
  p += 4;

  tag_ptr = p;
  auto tag_size = crypto_ctx.cipher->getTagSize();
  p += tag_size;

  if (crypto_ctx.cipher->isAEADMode()) {
    /* feed in tag and the authenticated data */
    const int ad_size = p - ad_start - tag_size;
    rc = crypto_ctx.cipher->updateAD(ad_start, ad_size);
  }

  int block_bytes = crypto_ctx.cipher->getBlockSize();

  std::vector<unsigned char> output_buffer(end - p + block_bytes);
  int output_bytes = 0;
  rc = crypto_ctx.cipher->updateData(p, end - p, output_buffer.data(), output_buffer.size());
  if (rc >= 0) {
    output_bytes += rc;
    if (crypto_ctx.cipher->isAEADMode()) {
      crypto_ctx.cipher->setAEADTag(tag_ptr);
    }
    rc = crypto_ctx.cipher->final(output_buffer.data() + rc, output_buffer.size() - rc);
    if (rc > 0) {
      output_bytes += rc;
    }
  }

  logger_->logf(Logger::kLogDebug, "decrypt: %d, %d", rc, output_bytes);
  dump(output_buffer.data(), output_bytes);
}

void ReliableLayer::processInboundKeyMethod(const char* data, int length) {
  do {
    int proceed_length;

    server_key_method_.init(true);
    proceed_length = server_key_method_.deserializeFrom((const unsigned char *) data, length);
    if (proceed_length < 0) {
      logger_->logf(Logger::kLogWarn, "processInboundKeyMethod: key_method parse failed: %d", proceed_length);
      state_ = kInitialState;
      break;
    }

    if (!server_data_channel_options_.deserialize(server_key_method_.optionsString())) {
      logger_->logf(Logger::kLogWarn, "processInboundKeyMethod: option_string parse failed: %d", proceed_length);
      state_ = kInitialState;
      break;
    }

    logger_->logf(Logger::kLogDebug, "server side option_string: %s", server_key_method_.optionsString().c_str());
  } while (0);

  if (protocol_config_.is_tls) {
    server_data_channel_options_.cipher = "AES-256-GCM";
    server_data_channel_options_.auth = "[null-digest]";
  }

  state_ = kGotKeyState;
  sessionProcess();
}

bool ReliableLayer::generateKeyExpansion(key2* pkey2) {
  //TODO: tls-ekm option
  return generateKeyExpansionOvpnPRF(pkey2);
}

bool ReliableLayer::generateKeyExpansionOvpnPRF(key2* pkey2) {
  uint8_t master[48] = { 0 };

  const auto& client_key_source = client_key_method_.keySource();
  const auto& server_key_source = server_key_method_.keySource();

  /* compute master secret */
  if (!openvpn_PRF(
      client_key_source.pre_master,
      sizeof(client_key_source.pre_master),
      KEY_EXPANSION_ID " master secret",
      client_key_source.random1,
      sizeof(client_key_source.random1),
      server_key_source.random1,
      sizeof(server_key_source.random1),
      nullptr,
      nullptr,
      master,
      sizeof(master)))
  {
    return false;
  }

  /* compute key expansion */
  if (!openvpn_PRF(
      master,
      sizeof(master),
      KEY_EXPANSION_ID " key expansion",
      client_key_source.random2,
      sizeof(client_key_source.random2),
      server_key_source.random2,
      sizeof(server_key_source.random2),
      client_session_id_,
      server_session_id_,
      (uint8_t *)pkey2->keys,
      sizeof(pkey2->keys)))
  {
    return false;
  }
  dump((uint8_t *)pkey2->keys, sizeof(pkey2->keys));

  RAND_bytes(master, sizeof(master));

  // DES not supported
  // fixup not included

  pkey2->n = 2;

  return true;
}

bool ReliableLayer::openvpn_PRF(
    const uint8_t *secret,
    int secret_len,
    const char *label,
    const uint8_t *client_seed,
    int client_seed_len,
    const uint8_t *server_seed,
    int server_seed_len,
    const unsigned char* client_sid,
    const unsigned char* server_sid,
    uint8_t *output,
    int output_len
) {
  std::vector<unsigned char> seed;
  seed.reserve(strlen(label) + client_seed_len + server_seed_len + sizeof(server_session_id_) + sizeof(client_session_id_));
  seed.insert(seed.end(), label, label + strlen(label));
  seed.insert(seed.end(), client_seed, client_seed + client_seed_len);
  seed.insert(seed.end(), server_seed, server_seed + server_seed_len);

  if (client_sid) {
    seed.insert(seed.end(), client_sid, client_sid + sizeof(client_session_id_));
  }
  if (server_sid) {
    seed.insert(seed.end(), server_sid, server_sid + sizeof(client_session_id_));
  }

  return tls_layer_->tls1Prf(
      seed.data(), seed.size(),
      secret, secret_len,
      output, output_len
  );
}

void ReliableLayer::sessionProcess() {
  bool server_mode = false;

  if (state_ == kInitialState) {
    sendControlHardResetClientV2();
    state_ = kPreStartState;
  }

  if (state_ == kStartState && !server_mode) {
    protocol::control::DataChannelOptions& data_channel_options = client_data_channel_options_;

    data_channel_options.version = "V4";
    data_channel_options.key_method = 2;
    data_channel_options.dev_type = "tun";
    data_channel_options.link_mtu = 1543;
    data_channel_options.tun_mtu = 1500;
    if (protocol_config_.is_tcp) {
      data_channel_options.proto = "tcp";
    } else {
      data_channel_options.proto = "udp";
    }
    data_channel_options.auth = "none";
    data_channel_options.key_size = 256;
    data_channel_options.cipher = "AES-256-GCM";
    data_channel_options.tls_direction = server_mode ? protocol::control::kTlsDirectionClient : protocol::control::kTlsDirectionServer;

    std::unique_ptr<char[]> raw_packet;
    client_key_method_.init(false);
    client_key_method_.setOptionString(data_channel_options.serialize());
    raw_packet.reset(new char[client_key_method_.getSerializedSize()]);
    client_key_method_.serializeTo((unsigned char *) raw_packet.get());

    logger_->logf(Logger::kLogDebug, "doKeyShare: %s", client_key_method_.optionsString().c_str());
    write(std::move(raw_packet), client_key_method_.getSerializedSize());
    state_ = kSentKeyState;
  }

  if (state_ == kGotKeyState) {
    key2 temp_key2;
    generateKeyExpansion(&temp_key2);
    initKeyContexts(&data_crypto_, &temp_key2, false, "Data Channel");
    state_ = kEstablishedState;
    logger_->logf(Logger::kLogDebug, "ReliableLayer: kEstablishedState");
  }
}

void ReliableLayer::initKeyContexts(BiCryptoContext* crypto_context, key2* pkey2, bool server_mode, const char* key_name) {
  char label[256];
  key* inbound_key = &pkey2->keys[server_mode ? kClientKey : kServerKey];
  key* outbound_key = &pkey2->keys[server_mode ? kServerKey : kClientKey];
  auto& inbound_data_channel_options = server_mode ? client_data_channel_options_ : server_data_channel_options_;
  auto& outbound_data_channel_options = server_mode ? server_data_channel_options_ : client_data_channel_options_;

  auto inbound_cipher_algorithm = crypto_provider_->getCipherAlgorithm(inbound_data_channel_options.cipher);
  auto inbound_auth_algorithm = crypto_provider_->getAuthAlgorithm(inbound_data_channel_options.auth);
  auto outbound_cipher_algorithm = crypto_provider_->getCipherAlgorithm(outbound_data_channel_options.cipher);
  auto outbound_auth_algorithm = crypto_provider_->getAuthAlgorithm(outbound_data_channel_options.auth);

  crypto_context->inbound.cipher = inbound_cipher_algorithm->createDecipher();
  crypto_context->inbound.hmac = inbound_auth_algorithm->create();
  crypto_context->outbound.cipher = outbound_cipher_algorithm->createEncipher();
  crypto_context->outbound.hmac = outbound_auth_algorithm->create();

  snprintf(label, sizeof(label), "Outgoing %s", key_name);
  crypto_context->outbound.cipher->init(outbound_key->cipher);
  printf("outgoing key : "); dump(outbound_key->cipher, sizeof(outbound_key->cipher));
  crypto_context->outbound.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
  if (crypto_context->outbound.hmac) {
    crypto_context->outbound.hmac->init(outbound_key->hmac);
  }
  crypto_context->outbound.setImplicitIV(outbound_key->hmac, MAX_HMAC_KEY_LENGTH);

  snprintf(label, sizeof(label), "Incoming %s", key_name);
  printf("Incoming key : "); dump(inbound_key->cipher, sizeof(inbound_key->cipher));
  crypto_context->inbound.cipher->init(inbound_key->cipher);
  crypto_context->inbound.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
  if (crypto_context->inbound.hmac) {
    crypto_context->inbound.hmac->init(inbound_key->hmac);
  }
  crypto_context->inbound.setImplicitIV(inbound_key->hmac, MAX_HMAC_KEY_LENGTH);
}

} // namespace transport
} // namespace ovpnc

