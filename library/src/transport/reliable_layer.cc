/**
 * @file	reliable_layer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-10
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <assert.h>

#include "reliable_layer.h"
#include "buffer_with_header.h"
#include "multiplexer.h"

#include "rw_buffer.h"

# define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
# define EVP_MAX_KEY_LENGTH              64
# define EVP_MAX_IV_LENGTH               16
# define EVP_MAX_BLOCK_LENGTH            32

//#include <cstring>
//#include <utility>
//
//#include <openssl/rand.h>
//#include <openssl/ssl.h>
//#include <ovpnc/tls_provider.h>
//
//#include "reliable_layer.h"
//
//#include "../protocol/reliable.h"
//#include "../protocol/control.h"

#define KEY_EXPANSION_ID "OpenVPN"

namespace ovpnc {
namespace transport {

#define KEY_ID_MASK 0x07 // 3bit (111b)

/*
 * This random string identifies an OpenVPN ping packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * PING_STRING_SIZE must be sizeof (ping_string)
 */
const uint8_t ping_string[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

static void dump(const void* ptr, int size) {
  const unsigned char* p = (const unsigned char*)ptr;
  fprintf(stderr, "DUMP (%d) \n", size);
  for (int i=0; i<size; i++) fprintf(stderr, "%02x ", *(p++));
  fprintf(stderr, "\n");
}

ReliableLayer::SessionContext::SessionContext() {
  std::memset(&session_id, 0, sizeof(session_id));
  packet_id = 0;
  data_packet_id = 0;
}

class ReliableLayer::SSLSocketMiddleware : public jcu::unio::StreamSocket {
 public:
  std::shared_ptr<ReliableLayer> reliable_;

  std::shared_ptr<jcu::unio::Buffer> read_buffer_;
  jcu::unio::CompletionManyCallback<jcu::unio::SocketReadEvent> read_callback_;

  SSLSocketMiddleware(std::shared_ptr<ReliableLayer> reliable) :
      reliable_(reliable) {
  }

  void emitRead() {
    if (read_callback_) {
      jcu::unio::SocketReadEvent event{read_buffer_.get()};
      read_callback_(event, *this);
    }
  }

  void read(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionManyCallback<jcu::unio::SocketReadEvent> callback
  ) override {
    read_buffer_ = buffer;
    read_callback_ = std::move(callback);
  }

  void cancelRead() override {
    read_buffer_.reset();
//    parent_socket_->cancelRead();
  }

  void write(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
  ) override {
    auto lazy_ack_context = reliable_->lazy_ack_context_;

    size_t header_capacity = buffer->position();
    int socket_header_size = reliable_->multiplexer_->getRequiredSocketHeader();
    uint32_t packet_id = reliable_->nextPacketId();
    protocol::reliable::ControlV1Payload control(protocol::reliable::OpCode::P_CONTROL_V1);
    reliable_->prepareSessionPayload(control);
    control.setPacketId(packet_id);
    if (lazy_ack_context && !lazy_ack_context->isSent() && !lazy_ack_context->getAckPacketIds().empty()) {
      int count = lazy_ack_context->getAckPacketIds().size();
      const uint32_t *acks = lazy_ack_context->getAckPacketIds().data();
      control.setAckPacketIdArrayLength(count);
      for (int i = 0; i < count; i++) {
        control.ackPacketIdArray()[i] = acks[i];
      }
      lazy_ack_context->setSent();
    }

    // set control
    int header_size = control.getSerializedSize();
    assert (header_capacity >= (socket_header_size + header_size));
    unsigned char *base_ptr = ((unsigned char *) buffer->data()) - header_size;
    control.serializeTo(base_ptr);
    buffer->position(header_capacity - header_size);

    reliable_->sendWithRetry(control.getOpCode(), packet_id, buffer, std::move(callback));
  }

  void connect(
      std::shared_ptr<jcu::unio::ConnectParam> connect_param,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketConnectEvent> callback
  ) override {
    jcu::unio::SocketConnectEvent event{};
    callback(event, *this);
  }

  void disconnect(
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketDisconnectEvent> callback
  ) override {
    jcu::unio::SocketDisconnectEvent event;
    callback(event, *this);
//    multiplexer_->parent_socket_->disconnect(std::move(callback));
  }

  bool isConnected() const override {
    return reliable_->multiplexer_->isConnected();
  }

  void close() override {
    read_callback_ = nullptr;
  }
};

std::shared_ptr<ReliableLayer> ReliableLayer::create(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger
) {
  auto instance = std::make_shared<ReliableLayer>(std::move(loop), std::move(logger));
  instance->self_ = instance;
  return std::move(instance);
}

ReliableLayer::ReliableLayer(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger
) :
    loop_(std::move(loop)),
    logger_(std::move(logger)),
    mode_(kClientMode),
    peer_inited_(false),
    lazy_ack_context_(nullptr),
    data_opcode_(protocol::reliable::P_DATA_V1) {
}

bool ReliableLayer::isHandshaked() const {
  return key_state_.state == kKeyStateEstablished;
}

ReliableLayer::SessionContext &ReliableLayer::getClientSession() {
  if (mode_ == kServerMode) return key_state_.peer;
  else return key_state_.local;
}

ReliableLayer::SessionContext &ReliableLayer::getServerSession() {
  if (mode_ == kServerMode) return key_state_.local;
  else return key_state_.peer;
}

const ReliableLayer::SessionContext &ReliableLayer::getClientSession() const {
  if (mode_ == kServerMode) return key_state_.peer;
  else return key_state_.local;
}

const ReliableLayer::SessionContext &ReliableLayer::getServerSession() const {
  if (mode_ == kServerMode) return key_state_.local;
  else return key_state_.peer;
}

void ReliableLayer::init(
    std::shared_ptr<Multiplexer> multiplexer,
    std::shared_ptr<jcu::unio::Buffer> send_message_buffer
) {
  std::shared_ptr<ReliableLayer> self(self_.lock());

  multiplexer_ = multiplexer;
  send_message_buffer_ = send_message_buffer;

  if (!vpn_config_.psk_mode) {
    ssl_socket_middleware_ = std::make_shared<SSLSocketMiddleware>(self);
    ssl_buffer_ = jcu::unio::createFixedSizeBuffer(8192);
    ssl_socket_ = jcu::unio::SSLSocket::create(loop_, logger_, vpn_config_.ssl_context);
    ssl_socket_->setParent(ssl_socket_middleware_);
    ssl_socket_->setSocketOutboundBuffer(send_message_buffer_);
  }
}

void ReliableLayer::start(const VPNConfig& vpn_config) {
  vpn_config_ = vpn_config;
  random_ = vpn_config_.crypto_provider->createRandom();
  random_->nextBytes(key_state_.local.session_id, sizeof(key_state_.local.session_id));
  key_state_.key_id = -1;
  keyStateInit();
}

void ReliableLayer::close() {
  multiplexer_.reset();
  send_message_buffer_.reset();
}

void ReliableLayer::keyStateInit() {
  if (key_state_.key_id < 0) {
    key_state_.key_id = 0;
  } else {
    // increment key_id
    key_state_.key_id = (key_state_.key_id + 1) & KEY_ID_MASK;
    if (!key_state_.key_id) key_state_.key_id = 1;
  }

  key_state_.state = kKeyStateInitial;
}

uint8_t ReliableLayer::getKeyId() const {
  return key_state_.key_id;
}

uint32_t ReliableLayer::nextPacketId() {
  return key_state_.local.packet_id++;
}

void ReliableLayer::sendWithRetry(
    uint8_t op_code,
    uint32_t packet_id,
    std::shared_ptr<jcu::unio::Buffer> buffer,
    jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
) {
  std::shared_ptr<ReliableLayer> self(self_.lock());
  auto temp_buffer =
      std::make_shared<BufferWithHeader>(
          self->multiplexer_->getRequiredMessageBufferOffset(),
          65536);
  temp_buffer->clear();

  std::memcpy(temp_buffer->data(), buffer->data(), buffer->remaining());
  temp_buffer->position(temp_buffer->position() + buffer->remaining());
  temp_buffer->flip();

  multiplexer_->write(
      op_code,
      buffer,
      [self, op_code, packet_id, temp_buffer, callback = std::move(callback)](
          auto &event,
          auto &handle
      ) mutable -> void {
        callback(event, handle);

        if (!event.hasError()) {
          LastSendPacket packet;

          packet.active = true;
          packet.buffer = temp_buffer;
          packet.op_code = op_code;
          packet.packet_id = packet_id;

          packet.timer = jcu::unio::Timer::create(self->loop_, self->logger_);
          packet.timer->on<jcu::unio::TimerEvent>([self, temp_buffer, op_code, packet_id](
              jcu::unio::TimerEvent &event,
              jcu::unio::Resource &handle
          ) -> void {
            self->logger_->logf(jcu::unio::Logger::kLogInfo, "RESEND: packet_id=%u", packet_id);
            auto &send_buffer = self->send_message_buffer_;
            send_buffer->clear();
            std::memcpy(send_buffer->data(), temp_buffer->data(), temp_buffer->remaining());
            send_buffer->position(send_buffer->position() + temp_buffer->remaining());
            send_buffer->flip();
            self->multiplexer_->write(
                op_code,
                send_buffer,
                [](jcu::unio::SocketWriteEvent &event,
                   jcu::unio::Resource &handle) -> void {
                  //
                });
          });
          packet.timer->start(
              std::chrono::milliseconds{3000},
              std::chrono::milliseconds{3000}
          );

          self->send_packets_.emplace_back(std::move(packet));
        }
      });
}

void ReliableLayer::prepareSessionPayload(protocol::reliable::SessionReliablePayload &payload) {
  payload.setSessionId(key_state_.local.session_id);
  payload.setRemoteSessionId(key_state_.peer.session_id);
}

ReliableLayer::UnwrapResult ReliableLayer::unwrap(
    ReliableLayer::LazyAckContext &ack_context,
    protocol::reliable::OpCode opcode,
    uint8_t key_id,
    const unsigned char *data,
    size_t length,
    jcu::unio::Buffer* output
) {
  int results = false;

  fprintf(stderr,
          "reliableProcess: unwrap: op=%d(%s), key_id=%d\n",
          opcode,
          protocol::reliable::ProtocolUtil::opcodeName(opcode),
          key_id
  );
  switch (opcode) {
    case protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V1:
    case protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V1:
    case protocol::reliable::P_CONTROL_SOFT_RESET_V1:
    case protocol::reliable::P_CONTROL_V1:
    case protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V2:
    case protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2:
    case protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V3:
      results = handleControlPayload(
          ack_context,
          opcode,
          key_id,
          data,
          length);
      break;
    case protocol::reliable::P_ACK_V1:
      results = handleAckV1Payload(ack_context, opcode, key_id, data, length);
      break;
    case protocol::reliable::P_DATA_V1:
    case protocol::reliable::P_DATA_V2:
      return unwrapDataPayload(opcode, key_id, data, length, output);
  }

  return results ? kUnwrapOk : kUnwrapFailed;
}

bool ReliableLayer::handleControlPayload(
    ReliableLayer::LazyAckContext &ack_context,
    protocol::reliable::OpCode op_code,
    uint8_t key_id,
    const unsigned char *data,
    size_t length
) {
  int results = 0;

  protocol::reliable::ControlV1Payload control_payload{op_code};
  int proceed_length = control_payload.deserializeFrom(data, length);
  if (proceed_length < 0) {
    logger_->logf(jcu::unio::Logger::kLogError, "ReliableLayer: handleControlPayload: deserialize failed");
    return false;
  }

  if (!preprocessPayload(control_payload)) {
    return false;
  }

  if (op_code == protocol::reliable::P_CONTROL_V1) {
    size_t data_size = length - proceed_length;
    auto &read_buffer = ssl_socket_middleware_->read_buffer_;
    assert(read_buffer != nullptr);
    lazy_ack_context_ = &ack_context;
    ssl_socket_middleware_->read_buffer_->clear();
    assert(data_size <= read_buffer->remaining());
    std::memcpy(read_buffer->data(), data + proceed_length, data_size);
    read_buffer->position(read_buffer->position() + data_size);
    read_buffer->flip();
    ssl_socket_middleware_->emitRead();
    lazy_ack_context_ = nullptr;
  }

  ack_context.addPacketId(control_payload.packetId());

  if ((control_payload.getOpCode() == protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2)
      || (control_payload.getOpCode() == protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V1)) {
    auto self(self_.lock());
    auto param = std::make_shared<jcu::unio::SockAddrConnectParam<sockaddr>>();
    param->setHostname(vpn_config_.remote_host);
    ssl_socket_->connect(param, [self](auto &event, auto &resource) -> void {
      auto &handle = dynamic_cast<jcu::unio::SSLSocket &>(resource);
      fprintf(stderr, "TLS HANDSHAKED!!!!!!!!!!!!!!!\n");
      handle.read(self->ssl_buffer_, [self](auto &event, auto &resource) -> void {
        self->handleTlsPayload(event.buffer());
      });
      self->key_state_.state = kKeyStateStart;
    });
  }

  return true;
}

//TODO: ssl_socket_->cancelRead()

void ReliableLayer::handleTlsPayload(jcu::unio::Buffer* buffer) {
  if (key_state_.state == kKeyStateSent) {
    auto &peer_session = key_state_.peer;

    peer_session.key_method.init(true);
    peer_session.key_method.deserializeFrom((const unsigned char *) buffer->data(), buffer->remaining());

    bool result = peer_session.data_channel_options.deserialize(peer_session.key_method.optionsString());

    fprintf(stderr, "PeerDataChannelOptions: deser=%d: %s\n", result, peer_session.key_method.optionsString().c_str());

    struct key2 temp_key2;
    generateKeyExpansion(&temp_key2);
    initKeyContexts(key_state_, &temp_key2, "Data Channel");
    key_state_.state = kKeyStateEstablished;
    logger_->logf(jcu::unio::Logger::kLogDebug, "ReliableLayer: kEstablishedState");

    startPushRequest();
  } else {
    std::string text_buffer((const char*)buffer->data(), buffer->remaining());

    if (text_buffer.compare(0, 11, "PUSH_REPLY,") == 0) {
      emitPushReply(text_buffer.c_str() + 11);
    }
  }
}

bool ReliableLayer::handleAckV1Payload(
    ReliableLayer::LazyAckContext &ack_context,
    protocol::reliable::OpCode op_code,
    uint8_t key_id,
    const unsigned char *data,
    size_t length
) {
  int results = 0;

  protocol::reliable::AckV1Payload ack_payload{op_code};
  int proceed_length = ack_payload.deserializeFrom(data, length);
  if (proceed_length < 0) {
    logger_->logf(jcu::unio::Logger::kLogError, "ReliableLayer: handleAckV1Payload: deserialize failed");
    return false;
  }

  if (!preprocessPayload(ack_payload)) {
    return false;
  }

  return true;
}

bool ReliableLayer::preprocessPayload(const protocol::reliable::SessionReliablePayload &payload) {
  //TODO: key_id 처리?

  // Check ACK
  if (payload.hasRemoteSessionId()) {
    if (std::memcmp(key_state_.local.session_id, payload.remoteSessionId(), sizeof(key_state_.local.session_id)) != 0) {
      logger_->logf(jcu::unio::Logger::kLogError, "ReliableLayer: preprocessPayload: invalid session id");
      return false;
    }
  }

  if ((payload.getOpCode() == protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2)
      || (payload.getOpCode() == protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V1)) {
    if (!peer_inited_) {
      std::memcpy(key_state_.peer.session_id, payload.sessionId(), sizeof(key_state_.peer.session_id));
      peer_inited_ = true;
    }
  }

  if (payload.ackPacketIdArrayLength() > 0) {
    handleReceivedAcks(payload);
  }

  return true;
}

void ReliableLayer::handleReceivedAcks(const protocol::reliable::SessionReliablePayload &payload) {
  int length = payload.ackPacketIdArrayLength();
  const uint32_t *packet_id_array = payload.ackPacketIdArray().data();

  for (int i = 0; i < length; i++) {
    logger_->logf(jcu::unio::Logger::kLogTrace, "ACK Received: packet_id=%u", packet_id_array[i]);
  }

  for (auto it = send_packets_.begin(); it != send_packets_.end();) {
    bool found = false;
    for (int i = 0; i < length; i++) {
      if (it->packet_id == packet_id_array[i]) {
        found = true;
        break;
      }
    }
    if (found) {
      it->clear();
      it = send_packets_.erase(it);
    } else {
      it++;
    }
  }
}

void ReliableLayer::sendControlHardResetClientV2() {
  auto buffer = multiplexer_->createMessageBuffer();
  uint32_t packet_id = nextPacketId();
  protocol::reliable::ControlV1Payload control(protocol::reliable::OpCode::P_CONTROL_HARD_RESET_CLIENT_V2);
  prepareSessionPayload(control);
  control.setPacketId(packet_id);
  buffer->clear();
  int header_size = control.getSerializedSize();
  control.serializeTo((unsigned char *) buffer->data());
  buffer->position(buffer->position() + header_size);
  buffer->flip();

  sendWithRetry(control.getOpCode(), packet_id, buffer, [](auto &event, auto &handle) -> void {
    //TODO: ERROR Handling
  });
}

void ReliableLayer::sendAckV1(
    int packet_id_count,
    const uint32_t *packet_ids,
    jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
) {
  auto buffer = multiplexer_->createMessageBuffer();

  protocol::reliable::AckV1Payload ack_payload{protocol::reliable::P_ACK_V1};
  ack_payload.setAckPacketIdArrayLength(packet_id_count);
  for (int i = 0; i < packet_id_count; i++) {
    ack_payload.ackPacketIdArray()[i] = packet_ids[i];
  }
  prepareSessionPayload(ack_payload);

  buffer->clear();
  int header_size = ack_payload.getSerializedSize();
  ack_payload.serializeTo((unsigned char *) buffer->data());
  buffer->position(buffer->position() + header_size);
  buffer->flip();

  multiplexer_->write(ack_payload.getOpCode(), buffer, std::move(callback));
}

void ReliableLayer::doNextOperationAndSendLazyAcks(
    ReliableLayer::LazyAckContext *ack_context
) {
  lazy_ack_context_ = ack_context;
  switch (key_state_.state) {
    case kKeyStateInitial:
      //      if (mode_ == kServerMode) {
//        next_op_ = protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2;
//      } else {
//        bool tls_crypt_v2 = false;
//        next_op_ = tls_crypt_v2 ? protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V3
//                                : protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V2;
//      }
      if (mode_ == kClientMode) {
        sendControlHardResetClientV2();
      }
      key_state_.state = kKeyStatePreStart;
      break;
    case kKeyStateStart:
      sendKeyState();
      break;
  }
  lazy_ack_context_ = nullptr;

  if (ack_context) {
    if (ack_context->isSent() || ack_context->getAckPacketIds().empty()) {
      return;
    }
    ack_context->setSent();
    fprintf(stderr, "doNextOperationAndSendLazyAcks count=%d\n", ack_context->getAckPacketIds().size());
    sendAckV1(
        ack_context->getAckPacketIds().size(),
        ack_context->getAckPacketIds().data(),
        [](auto &event, auto &handle) -> void {
          //TODO: ERROR HANDLING
        });
  }
}

ReliableLayer::UnwrapResult ReliableLayer::unwrapDataPayload(
    protocol::reliable::OpCode opcode,
    uint8_t key_id,
    const unsigned char *data,
    size_t length,
    jcu::unio::Buffer* output
) {
  auto& inbound_crypto = key_state_.inbound_crypto;

  const unsigned char *p = data;
  const unsigned char *end = data + length;

  const unsigned char* ad_start = nullptr;
  const unsigned char* tag_ptr = nullptr;

  int rc = 0;

  /*
   * P_DATA message content:
   *   HMAC of ciphertext IV + ciphertext (if not disabled by
   *       --auth none).
   *   Ciphertext IV (size is cipher-dependent, if not disabled by
   *       --no-iv).
   *   Tunnel packet ciphertext.
   */

  if (opcode == protocol::reliable::P_DATA_V2)
  {
    data_opcode_ = protocol::reliable::P_DATA_V2;
    ad_start = p - 1;
    p += 3;
  } else if (opcode == protocol::reliable::P_DATA_V1) {
    ad_start = p;
  }

//  if (inbound_crypto.hmac) {
//    size_t auth_size = inbound_crypto.hmac->getOutputSize();
//    const unsigned char* auth_data = data;
//    data += auth_size;
//    length -= auth_size;
//  }

  uint32_t packet_id = protocol::reliable::deserializeUint32(p);
  /* Combine IV from explicit part from packet and implicit part from context */
  {
    uint8_t iv[EVP_MAX_IV_LENGTH] = { 0 };
    //BUFFER OVERFLOW CHECK
    const int iv_len = inbound_crypto.cipher->getIVSize();
    const size_t packet_iv_len = iv_len - inbound_crypto.implicit_iv.size();
    memcpy(iv, p, packet_iv_len);
    memcpy(iv + packet_iv_len, inbound_crypto.implicit_iv.data(), inbound_crypto.implicit_iv.size());
    inbound_crypto.cipher->reset(iv);
  }
  p += 4;

  tag_ptr = p;
  auto tag_size = 0;
  if (inbound_crypto.cipher->isAEADMode()) {
    /* feed in tag and the authenticated data */
    const int ad_size = p - ad_start;
    tag_size = inbound_crypto.cipher->getTagSize();
    rc = inbound_crypto.cipher->updateAD(ad_start, ad_size);
    fprintf(stderr, "INBOUND>cipher->updateAD rc=%d\n", rc);
  }
  p += tag_size;

  int block_bytes = inbound_crypto.cipher->getBlockSize();

  output->clear();
  size_t output_size = end - p + block_bytes;
  assert (output->remaining() >= output_size);

  int output_bytes = 0;
  rc = inbound_crypto.cipher->updateData(p, end - p, (unsigned char*)output->data(), output->remaining());
  fprintf(stderr, "INBOUND>cipher->updateData rc=%d\n", rc);
  if (rc >= 0) {
    output_bytes += rc;
    if (inbound_crypto.cipher->isAEADMode()) {
      inbound_crypto.cipher->setAEADTag(tag_ptr);
    }
    rc = inbound_crypto.cipher->final((unsigned char*)output->data() + rc, output->remaining() - rc);
    fprintf(stderr, "INBOUND>cipher->final rc=%d\n", rc);
    if (rc > 0) {
      output_bytes += rc;
    }
  }
  output->position(output->position() + output_bytes);
  output->flip();

  if ((output->remaining() == sizeof(ping_string)) && (std::memcmp(output->data(), ping_string, sizeof(ping_string)) == 0)) {
    // If ping payload
    //TODO: Idle 시 PING 처리
    return kUnwrapOk;
  }

  return kUnwrapData;
}

bool ReliableLayer::wrapData(
    jcu::unio::Buffer *input,
    jcu::unio::Buffer *output,
    uint8_t *popcode
) {
  protocol::reliable::OpCode data_op_code = data_opcode_;

  auto& outbound_crypto = key_state_.outbound_crypto;

  int rc = 0;

  output->clear();
  RWBuffer writer(output);

  unsigned char* ad_start = nullptr;

  if (data_op_code == protocol::reliable::P_DATA_V2) {
    if (output->position() < 1) {
      return false;
    }
    ad_start = ((unsigned char*)output->data()) - 1;
    ad_start[0] = ((uint8_t)data_op_code) << 3 | key_state_.key_id; // P_DATA_V2
    writer.writeUint8(0);
    writer.writeUint8(0);
    if (!writer.writeUint8(0)) {
      return false;
    }
//    peer = htonl(((P_DATA_V2 << P_OPCODE_SHIFT) | ks->key_id) << 24
//                     | (multi->peer_id & 0xFFFFFF));
//    ASSERT(buf_write_prepend(buf, &peer, 4));
  } else {
    ad_start = ((unsigned char*)output->data());
  }

  uint32_t packet_id = ++key_state_.local.data_packet_id;

  const unsigned char* packet_iv_ptr = writer.data();
  if (!writer.writeUint32(packet_id)) {
    return false;
  }

  /* Combine IV from explicit part from packet and implicit part from context */
  {
    uint8_t iv[EVP_MAX_IV_LENGTH] = { 0 };
    const int iv_len = outbound_crypto.cipher->getIVSize();
    const size_t packet_iv_len = iv_len - outbound_crypto.implicit_iv.size();

    // packet_id
    memcpy(iv, packet_iv_ptr, packet_iv_len);
    memcpy(iv + packet_iv_len, outbound_crypto.implicit_iv.data(), outbound_crypto.implicit_iv.size());

    outbound_crypto.cipher->reset(iv);
  }

  if (outbound_crypto.cipher->isAEADMode()) {
    const unsigned char* ad_end = writer.data();
    /* feed in tag and the authenticated data */
    int ad_size = ad_end - ad_start;
    rc = outbound_crypto.cipher->updateAD(ad_start, ad_size);
    fprintf(stderr, "OUTBOUND>cipher->updateAD rc=%d\n", rc);
  }

  unsigned char* tag_ptr = writer.data();
  if (outbound_crypto.cipher->isAEADMode()) {
    auto tag_size = outbound_crypto.cipher->getTagSize();
    writer.skip(tag_size);
  }

  int block_bytes = outbound_crypto.cipher->getBlockSize();

  rc = outbound_crypto.cipher->updateData((const unsigned char*) input->data(), input->remaining(), writer.data(), writer.remaining());
  if (rc < 0) {
    fprintf(stderr, "OUTBOUND>cipher->updateData rc=%d\n", rc);
    return false;
  }
  writer.skip(rc);

  rc = outbound_crypto.cipher->final(writer.data(), writer.remaining());
  if (rc < 0) {
    fprintf(stderr, "OUTBOUND>cipher->updateData rc=%d\n", rc);
    return false;
  }
  writer.skip(rc);

  if (outbound_crypto.cipher->isAEADMode()) {
    outbound_crypto.cipher->getAEADTag(tag_ptr);
  }

  writer.flip();

  *popcode = data_op_code;
  return true;
}

//region OpenVPN Key Exchange

bool ReliableLayer::openvpn_PRF(
    const uint8_t *secret,
    int secret_len,
    const char *label,
    const uint8_t *client_seed,
    int client_seed_len,
    const uint8_t *server_seed,
    int server_seed_len,
    const unsigned char *client_sid,
    const unsigned char *server_sid,
    uint8_t *output,
    int output_len
) {
  const int session_id_size = 8;

  std::vector<unsigned char> seed;
  seed.reserve(strlen(label) + sizeof(client_seed) + sizeof(server_seed) + session_id_size * 2);
  seed.insert(seed.end(), label, label + strlen(label));
  seed.insert(seed.end(), client_seed, client_seed + client_seed_len);
  seed.insert(seed.end(), server_seed, server_seed + server_seed_len);

  if (client_sid) {
    seed.insert(seed.end(), client_sid, client_sid + session_id_size);
  }
  if (server_sid) {
    seed.insert(seed.end(), server_sid, server_sid + session_id_size);
  }

  return vpn_config_.ssl_context->getProvider()->tls1Prf(
      seed.data(), seed.size(),
      secret, secret_len,
      output, output_len
  );
}

bool ReliableLayer::generateKeyExpansion(struct key2 *pkey2) {
  //TODO: tls-ekm option
  return generateKeyExpansionOvpnPRF(pkey2);
}

bool ReliableLayer::generateKeyExpansionOvpnPRF(struct key2 *pkey2) {
  uint8_t master[48] = {0};

  const auto &client_key_source = getClientSession().key_method.keySource();
  const auto &server_key_source = getServerSession().key_method.keySource();
  const auto &client_sid = getClientSession().session_id;
  const auto &server_sid = getServerSession().session_id;

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
      sizeof(master))) {
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
      client_sid,
      server_sid,
      (uint8_t *) pkey2->keys,
      sizeof(pkey2->keys))) {
    return false;
  }

  random_->nextBytes(master, sizeof(master));

  // DES not supported
  // fixup not included

  pkey2->n = 2;

  return true;
}

void ReliableLayer::startPushRequest() {
  std::shared_ptr<ReliableLayer> self(self_.lock());

  if (push_request_timer_) {
    push_request_timer_->close();
  }
  push_request_timer_ = jcu::unio::Timer::create(loop_, logger_);
  push_request_timer_->on<jcu::unio::TimerEvent>([self](auto& event, auto& resource) -> void {
    self->sendPushRequest();
  });
  push_request_timer_->start(
      std::chrono::milliseconds { 500 },
      std::chrono::milliseconds { 30000 }
  );
}

void ReliableLayer::sendPushRequest() {
  const char MESSAGE[] = "PUSH_REQUEST";
  auto buffer = jcu::unio::createFixedSizeBuffer(strlen(MESSAGE) + 1);
  buffer->clear();
  std::memcpy(buffer->data(), MESSAGE, strlen(MESSAGE) + 1);
  buffer->position(buffer->position() + strlen(MESSAGE) + 1);
  buffer->flip();
  ssl_socket_->write(buffer, [](auto &event, auto &handle) -> void {

  });
}

void ReliableLayer::sendKeyState() {
  protocol::control::DataChannelOptions &data_channel_options = key_state_.local.data_channel_options;

  data_channel_options.version = "V4";
  data_channel_options.key_method = 2;
  data_channel_options.dev_type = "tun";
  data_channel_options.link_mtu = 1543;
  data_channel_options.tun_mtu = 1500;
  if (vpn_config_.protocol == kTransportTcp) {
    data_channel_options.proto = "tcp";
  } else {
    data_channel_options.proto = "udp";
  }
  data_channel_options.auth = "none";
  data_channel_options.key_size = 256;
  data_channel_options.cipher = "AES-256-GCM";
  data_channel_options.tls_direction =
      (mode_ == kServerMode) ? protocol::control::kTlsDirectionServer : protocol::control::kTlsDirectionClient;

  key_state_.local.key_method.init(false);
  key_state_.local.key_method.setOptionString(data_channel_options.serialize());

  size_t serialized_size = key_state_.local.key_method.getSerializedSize();
  auto buffer = jcu::unio::createFixedSizeBuffer(serialized_size);
  buffer->clear();
  key_state_.local.key_method.serializeTo((unsigned char *) buffer->data());
  buffer->position(buffer->position() + serialized_size);
  buffer->flip();

  fprintf(stderr, "doKeyShare: %s\n", key_state_.local.key_method.optionsString().c_str());

  key_state_.state = kKeyStateSent;
  ssl_socket_->write(buffer, [](auto &event, auto &handle) -> void {

  });
}

void ReliableLayer::initKeyContexts(KeyState& key_state, key2* pkey2, const char* key_name) {
  char label[256];

  auto& inbound_options = (mode_ == kServerMode) ? key_state_.local.data_channel_options : key_state_.peer.data_channel_options;
  auto& outbound_options = (mode_ == kServerMode) ? key_state_.peer.data_channel_options : key_state_.local.data_channel_options;

  auto inbound_cipher_algorithm = vpn_config_.crypto_provider->getCipherAlgorithm(inbound_options.cipher);
  auto inbound_auth_algorithm = vpn_config_.crypto_provider->getAuthAlgorithm(inbound_options.auth);
  auto outbound_cipher_algorithm = vpn_config_.crypto_provider->getCipherAlgorithm(outbound_options.cipher);
  auto outbound_auth_algorithm = vpn_config_.crypto_provider->getAuthAlgorithm(outbound_options.auth);

  //TODO: critical! NULL HANDLING
  //      WHY... BF-CBC & SHA1 :(

  key_state_.inbound_crypto.cipher = inbound_cipher_algorithm->createDecipher();
  key_state_.inbound_crypto.hmac = inbound_auth_algorithm->create();
  key_state_.outbound_crypto.cipher = outbound_cipher_algorithm->createEncipher();
  key_state_.outbound_crypto.hmac = outbound_auth_algorithm->create();

  auto& incoming_crypto = (mode_ == kServerMode) ? key_state_.outbound_crypto : key_state_.inbound_crypto;
  auto& outgoing_crypto = (mode_ == kServerMode) ? key_state_.inbound_crypto : key_state_.outbound_crypto;

  snprintf(label, sizeof(label), "Outgoing %s", key_name);
  outgoing_crypto.cipher->init(pkey2->keys[0].cipher);
  outgoing_crypto.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
  if (outgoing_crypto.hmac) {
    outgoing_crypto.hmac->init(pkey2->keys[0].hmac);
  }
  outgoing_crypto.setImplicitIV(pkey2->keys[0].hmac, MAX_HMAC_KEY_LENGTH);

  snprintf(label, sizeof(label), "Incoming %s", key_name);
  incoming_crypto.cipher->init(pkey2->keys[1].cipher);
  incoming_crypto.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
  if (incoming_crypto.hmac) {
    incoming_crypto.hmac->init(pkey2->keys[1].hmac);
  }
  incoming_crypto.setImplicitIV(pkey2->keys[1].hmac, MAX_HMAC_KEY_LENGTH);
}


void ReliableLayer::emitPushReply(const char* data) {
  last_push_reply_ = data;
  if (push_reply_callback_) {
    push_reply_callback_(last_push_reply_);
  }
}

void ReliableLayer::onPushReply(std::function<void(const std::string& options)> callback) {
  if (!last_push_reply_.empty()) {
    callback(last_push_reply_);
  }
  push_reply_callback_ = std::move(callback);
}

//endregion

} // namespace transport
} // namespace ovpnc
