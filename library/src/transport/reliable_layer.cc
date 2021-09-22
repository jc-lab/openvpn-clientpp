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

static void dump(const void* ptr, int size) {
  const unsigned char* p = (const unsigned char*)ptr;
  fprintf(stderr, "DUMP (%d) \n", size);
  for (int i=0; i<size; i++) fprintf(stderr, "%02x ", *(p++));
  fprintf(stderr, "\n");
}

ReliableLayer::SessionContext::SessionContext() {
  std::memset(&session_id, 0, sizeof(session_id));
  packet_id = 0;
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
    read_callback_ = nullptr;
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
  }
};

std::shared_ptr<ReliableLayer> ReliableLayer::create(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger,
    VPNConfig vpn_config
) {
  auto instance = std::make_shared<ReliableLayer>(std::move(loop), std::move(logger), std::move(vpn_config));
  instance->self_ = instance;
  return std::move(instance);
}

ReliableLayer::ReliableLayer(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger,
    VPNConfig vpn_config
) :
    loop_(loop),
    logger_(logger),
    vpn_config_(vpn_config),
    mode_(kClientMode),
    peer_inited_(false),
    lazy_ack_context_(nullptr) {
  random_ = vpn_config_.crypto_provider->createRandom();
  random_->nextBytes(key_state_.local.session_id, sizeof(key_state_.local.session_id));
  key_state_.key_id = -1;
  keyStateInit();
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
          "reliableProcess: unwrap: op = %d / %s\n",
          opcode,
          protocol::reliable::ProtocolUtil::opcodeName(opcode));

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
  auto& peer_session = key_state_.peer;

  peer_session.key_method.init(true);
  peer_session.key_method.deserializeFrom((const unsigned char*) buffer->data(), buffer->remaining());

  bool result = peer_session.data_channel_options.deserialize(peer_session.key_method.optionsString());
  fprintf(stderr, "handleTlsPayload: size=%d : %s : deser=%d\n", buffer->remaining(), peer_session.key_method.optionsString().c_str(), result);

  struct key2 temp_key2;
  generateKeyExpansion(&temp_key2);
  initKeyContexts(key_state_, &temp_key2, "Data Channel");
  key_state_.state = kKeyStateEstablished;
  logger_->logf(jcu::unio::Logger::kLogDebug, "ReliableLayer: kEstablishedState");
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
  auto& inbound_session = key_state_.peer;
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

  uint32_t packet_id = protocol::reliable::deserializeUint32(data);
  p += 4;

  tag_ptr = p;
  auto tag_size = inbound_crypto.cipher->getTagSize();
  p += tag_size;

  if (inbound_crypto.cipher->isAEADMode()) {
    /* feed in tag and the authenticated data */
    const int ad_size = p - ad_start - tag_size;

    rc = inbound_crypto.cipher->updateAD(ad_start, ad_size);
    fprintf(stderr, "INBOUND>cipher->updateAD rc=%d\n", rc);
  }

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

  return kUnwrapData;
}

//
//void ReliableLayer::processData(protocol::reliable::OpCode op_code, const unsigned char *op_begin, const unsigned char *raw_payload, int length) {
//  const unsigned char *p = raw_payload;
//  const unsigned char *end = raw_payload + length;
//  bool no_iv = false;
//  auto& crypto_ctx = data_crypto_.inbound;
//  const unsigned char* ad_start;
//  uint32_t packet_id = 0;
//  const unsigned char* tag_ptr = nullptr;
//  int rc;
//
//  dump(p, end - p);
//
//  if (op_code == protocol::reliable::P_DATA_V2)
//  {
//    ad_start = op_begin;
//    p += 3;
//  } else if (op_code == protocol::reliable::P_DATA_V1) {
//    ad_start = raw_payload;
//  }
//
//  /* Combine IV from explicit part from packet and implicit part from context */
//  {
//    uint8_t iv[EVP_MAX_IV_LENGTH] = { 0 };
//    const int iv_len = crypto_ctx.cipher->getIVSize();
//    const size_t packet_iv_len = iv_len - crypto_ctx.implicit_iv.size();
//    memcpy(iv, p, packet_iv_len);
//    memcpy(iv + packet_iv_len, crypto_ctx.implicit_iv.data(), crypto_ctx.implicit_iv.size());
//    printf("DECRYPT IV : ");
//    dump(iv, iv_len);
//    crypto_ctx.cipher->reset(iv);
//  }
//
//  packet_id = protocol::reliable::deserializeUint32(p);
//  p += 4;
//
//  tag_ptr = p;
//  auto tag_size = crypto_ctx.cipher->getTagSize();
//  p += tag_size;
//
//  if (crypto_ctx.cipher->isAEADMode()) {
//    /* feed in tag and the authenticated data */
//    const int ad_size = p - ad_start - tag_size;
//    rc = crypto_ctx.cipher->updateAD(ad_start, ad_size);
//  }
//
//  int block_bytes = crypto_ctx.cipher->getBlockSize();
//
//  std::vector<unsigned char> output_buffer(end - p + block_bytes);
//  int output_bytes = 0;
//  rc = crypto_ctx.cipher->updateData(p, end - p, output_buffer.data(), output_buffer.size());
//  if (rc >= 0) {
//    output_bytes += rc;
//    if (crypto_ctx.cipher->isAEADMode()) {
//      crypto_ctx.cipher->setAEADTag(tag_ptr);
//    }
//    rc = crypto_ctx.cipher->final(output_buffer.data() + rc, output_buffer.size() - rc);
//    if (rc > 0) {
//      output_bytes += rc;
//    }
//  }
//
//  logger_->logf(Logger::kLogDebug, "decrypt: %d, %d", rc, output_bytes);
//  dump(output_buffer.data(), output_bytes);
//}
//

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

//endregion

//static void dump(const void* ptr, int length) {
//  const unsigned char* c = (const unsigned char*)ptr;
//  for (int i=0; i<length; i++) {
//    printf("%02x ", c[i]);
//  }
//  printf("\n");
//}
//
//
//ReliableLayer::ReliableLayer(
//    std::shared_ptr<Logger> logger,
//    std::shared_ptr<Transport> transport,
//    ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
//    std::shared_ptr<crypto::Provider> crypto_provider
//) :
//    logger_(std::move(logger)),
//    transport_(std::move(transport)),
//    tls_layer_supplier_(std::move(tls_layer_supplier)),
//    crypto_provider_(std::move(crypto_provider)),
//    cleanup_(false),
//    state_(kNotStarted) {
//  logger_->logf(Logger::kLogDebug, "ReliableLayer: Construct");
//
//  recv_buffer_.resize(65536);
//
//  transport_->onceConnectEvent([](Transport *transport) -> void {
//    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
//
//    self->logger_->logf(Logger::kLogDebug, "ReliableLayer: transport connected");
//
//    self->sessionInit();
//    transport->read();
//
//    self->state_ = kInitialState;
//    self->sessionProcess();
//  });
//  transport_->onDataEvent([](Transport *transport, Transport::DataEvent &event) -> void {
//    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
//    self->processInbound(event);
//  });
//  transport_->onceErrorEvent([](Transport *transport, uvw::ErrorEvent &event) -> void {
//    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
//    if (self->error_handler_) {
//      self->error_handler_(self.get(), event);
//    }
//    // Should the parent automatically closes when an error occurs.
//  });
//  transport_->onceCloseEvent([](Transport *transport) -> void {
//    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
//    if (self->close_handler_) {
//      self->close_handler_(self.get());
//    }
//  });
//  transport_->onceCleanupEvent([](Transport *transport) -> void {
//    std::shared_ptr<ReliableLayer> self(transport->template data<ReliableLayer>());
//    self->cleanup();
//  });
//}
//
//ReliableLayer::~ReliableLayer() {
//  logger_->logf(Logger::kLogDebug, "ReliableLayer: Deconstruct");
//}
//
//std::shared_ptr<ReliableLayer> ReliableLayer::create(
//    std::shared_ptr<Logger> logger,
//    std::shared_ptr<Transport> parent,
//    ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
//    std::shared_ptr<crypto::Provider> crypto_provider
//    ) {
//  std::shared_ptr<ReliableLayer> instance(new ReliableLayer(
//      std::move(logger),
//      std::move(parent),
//      std::move(tls_layer_supplier),
//      crypto_provider
//  ));
//  instance->self_ = instance;
//  instance->transport_->data(instance);
//  instance->tlsInit();
//  return std::move(instance);
//}
//
//std::shared_ptr<Loop> ReliableLayer::getLoop() {
//  return transport_->getLoop();
//}
//
//void ReliableLayer::connect(const sockaddr *addr) {
//  state_ = kNotStarted;
//  transport_->connect(addr);
//}
//
//void ReliableLayer::connect(const uvw::Addr &addr) {
//  state_ = kNotStarted;
//  transport_->connect(addr);
//}
//
//void ReliableLayer::read() {
//  // nothing
//}
//
//void ReliableLayer::write(std::unique_ptr<char[]> data, unsigned int len) {
//  if (protocol_config_.is_tls) {
//    tls_layer_->write(std::move(data), len);
//  }
//}
//
//void ReliableLayer::onceConnectEvent(const ConnectEventHandler_t &handler) {
//  connect_handler_ = handler;
//}
//
//void ReliableLayer::onDataEvent(const Transport::DataEventHandler_t &handler) {
//  data_handler_ = handler;
//}
//
//void ReliableLayer::onceCloseEvent(const Transport::CloseEventHandler_t &handler) {
//  close_handler_ = handler;
//}
//
//void ReliableLayer::onceErrorEvent(const ErrorEventHandler_t &handler) {
//  error_handler_ = handler;
//}
//
//void ReliableLayer::onceCleanupEvent(const CleanupHandler_t &handler) {
//  cleanup_handler_ = handler;
//}
//
//void ReliableLayer::shutdown() {
//  transport_->shutdown();
//}
//
//void ReliableLayer::close() {
//  transport_->close();
//}
//
//void ReliableLayer::cleanup() {
//  std::shared_ptr<ReliableLayer> self(self_.lock()); // Keep reference
//
//  if (cleanup_) return;
//  cleanup_ = true;
//  error_handler_ = nullptr;
//  if (cleanup_handler_) {
//    cleanup_handler_(this);
//  }
//  cleanup_handler_ = nullptr;
//  transport_->data(nullptr);
//}
//
//static unsigned readUint16FromPacket(const unsigned char *ptr) {
//  unsigned int x = ((unsigned int) ptr[0]) << 8;
//  x |= ((unsigned int) ptr[1]);
//  return x;
//}
//
//void ReliableLayer::sessionInit() {
//  recv_position_ = 0;
//  client_packet_id_ = 0;
//  server_packet_id_ = 0;
//  RAND_bytes(client_session_id_, sizeof(client_session_id_));
//  std::memset(server_session_id_, 0, sizeof(server_session_id_));
//}
//
//void ReliableLayer::sendControlHardResetClientV2() {
//  protocol::reliable::ControlV1Payload control_payload{protocol::reliable::P_CONTROL_HARD_RESET_CLIENT_V2};
//  control_payload.setSessionId(client_session_id_);
//  control_payload.setAckPacketIdArrayLength(0);
//  control_payload.setPacketId(client_packet_id_++);
//
//  logger_->logf(Logger::kLogDebug, "ReliableLayer: sendControlHardResetClientV2");
//
//  state_ = kPreStartState;
//  sendSimplePayload(&control_payload);
//}
//
//void ReliableLayer::processInbound(Transport::DataEvent &event) {
//  unsigned char *recv_buffer_ptr = recv_buffer_.data();
//  int offset = 0;
//
//  logger_->logf(Logger::kLogDebug, "processData: %d", event.length);
//
//  do {
//    int recv_available = event.length - offset;
//    int packet_length = 2;
//    if (recv_position_ >= 2) {
//      packet_length = 2 + readUint16FromPacket(recv_buffer_ptr);
//      if (packet_length == recv_position_) {
//        logger_->logf(Logger::kLogDebug, "a packet: %d", packet_length);
//        processPacketInbound(recv_buffer_ptr, packet_length);
//        recv_position_ = 0;
//        packet_length = 2;
//      }
//    }
//    if (event.length == offset) {
//      break;
//    }
//    int packet_remaining = packet_length - recv_position_;
//    int copy_length = (packet_remaining > recv_available) ? recv_available : packet_remaining;
//    // assert (copy_length > 0);
//
//    std::memcpy(recv_buffer_ptr + recv_position_, event.data.get() + offset, copy_length);
//    recv_position_ += copy_length;
//    offset += copy_length;
//  } while (true);
//}
//
//void ReliableLayer::processPacketInbound(const unsigned char *buffer, int length) {
//  auto config = transport_->getProtocolConfig();
//  const unsigned char *p = buffer;
//  const unsigned char *end = buffer + length;
//  const unsigned char* op_begin = nullptr;
//  uint8_t op_code;
//  uint8_t key_id;
//  if (config->is_tcp) {
//    p += 2;
//  } else {
//    logger_->logf(Logger::kLogError, "ReliableLayer: non-tcp not supported yet");
//    return;
//  }
//
//  op_begin = p;
//  if (config->is_tls) {
//    op_code = (*p >> 3) & 0x1f;
//    key_id = *p & 0x7;
//    p++;
//  } else {
//    logger_->logf(Logger::kLogError, "ReliableLayer: non-tls not supported yet");
//    return;
//  }
//
//  logger_->logf(
//      Logger::kLogDebug,
//      "ReliableLayer: processPacketInbound: op_code=%u, key_id=%u, size=%d",
//      op_code,
//      key_id,
//      length
//  );
//
//  switch (op_code) {
//    case protocol::reliable::P_CONTROL_HARD_RESET_SERVER_V2:
//      processControlHardResetServerV2(
//          (protocol::reliable::OpCode) op_code,
//          p,
//          end - p
//      );
//      break;
//    case protocol::reliable::P_CONTROL_V1:
//      processControlV1((protocol::reliable::OpCode) op_code, p, end - p);
//      break;
//    case protocol::reliable::P_DATA_V1:
//    case protocol::reliable::P_DATA_V2:
//      processData((protocol::reliable::OpCode) op_code, op_begin, p, end - p);
//      break;
//    default:
//      logger_->logf(
//          Logger::kLogDebug,
//          "ReliableLayer: processPacketInbound: op_code=%u: Not supported yet",
//          op_code
//      );
//  }
//}
//
//void ReliableLayer::processControlHardResetServerV2(
//    protocol::reliable::OpCode op_code,
//    const unsigned char *raw_payload,
//    int length
//) {
//  protocol::reliable::ControlV1Payload control_payload{op_code};
//  int proceed_length = control_payload.deserializeFrom(raw_payload, length);
//  if (proceed_length < 0) {
//    logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: deserialize failed");
//    return;
//  }
//
//  // Check ACK
//  if (control_payload.hasRemoteSessionId()) {
//    if (std::memcmp(client_session_id_, control_payload.remoteSessionId(), sizeof(client_session_id_)) != 0) {
//      logger_->logf(Logger::kLogError, "ReliableLayer: processControlHardResetServerV2: invalid session id");
//      return;
//    }
//  }
//
//  std::memcpy(server_session_id_, control_payload.sessionId(), sizeof(server_session_id_));
//
//  uint32_t ack_packet_ids[1] = {
//      control_payload.packetId()
//  };
//  sendAckV1(1, ack_packet_ids);
//
//  if (protocol_config_.is_tls) {
//    tls_layer_->tlsReset();
//    tls_layer_->tlsOperation(TlsLayer::kTlsOpHandshake);
//  } else {
//    state_ = kStartState;
//    sessionProcess();
//  }
//}
//
////TODO: 패킷 합쳐서 보내기 (Ack를 Control패킷에)
//
//void ReliableLayer::processControlV1(protocol::reliable::OpCode op_code, const unsigned char *raw_payload, int length) {
//  protocol::reliable::ControlV1Payload control_payload{op_code};
//  int offset = control_payload.deserializeFrom(raw_payload, length);
//  if (offset < 0) {
//    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: deserialize failed");
//    return;
//  }
//  if (control_payload.hasRemoteSessionId()) {
////  if (!control_payload.hasRemoteSessionId()) {
////    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: not supported case#01");
////    return ;
////  }
//    if (std::memcmp(client_session_id_, control_payload.remoteSessionId(), sizeof(client_session_id_))) {
//      logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: invalid session id");
//      return;
//    }
//  }
//  if (std::memcmp(server_session_id_, control_payload.sessionId(), sizeof(server_session_id_)) != 0) {
//    logger_->logf(Logger::kLogError, "ReliableLayer: processControlV1: invalid peer's session id");
//    return;
//  }
//
//  if (protocol_config_.is_tls) {
//    tls_layer_->feedInboundCipherText(raw_payload + offset, length - offset);
//  }
//
//  uint32_t ack_packet_ids[1] = {
//      control_payload.packetId()
//  };
//  sendAckV1(1, ack_packet_ids);
//}
//
//void ReliableLayer::initControlV1PayloadToSend(protocol::reliable::ControlV1Payload *payload) {
//  payload->setSessionId(client_session_id_);
//  payload->setRemoteSessionId(server_session_id_);
//  payload->setPacketId(client_packet_id_++);
//}
//
//void ReliableLayer::initAckV1PayloadToSend(protocol::reliable::AckV1Payload *payload) {
//  payload->setSessionId(client_session_id_);
//  payload->setRemoteSessionId(server_session_id_);
//}
//
//void ReliableLayer::sendSimplePayload(const protocol::reliable::ReliablePayload *payload) {
//  protocol::reliable::UniqueCharArrPacketWriter packet_writer{transport_->getProtocolConfig()};
//  packet_writer.prepare(payload, 0);
//  packet_writer.write(0);
//  transport_->write(std::move(packet_writer.buffer), packet_writer.getPacketLength());
//}
//
//// TLS
//
//void ReliableLayer::tlsInit() {
//  std::weak_ptr<ReliableLayer> weak_self(self_);
//  tls_layer_ = tls_layer_supplier_(weak_self.lock());
//  tls_layer_->onceConnectEvent([weak_self](Transport *transport) -> void {
//    std::shared_ptr<ReliableLayer> self(weak_self.lock());
//    self->state_ = kStartState;
//    self->sessionProcess();
//  });
//  tls_layer_->onceErrorEvent([weak_self](Transport *transport, uvw::ErrorEvent &event) -> void {
//    std::shared_ptr<ReliableLayer> self(weak_self.lock());
//    if (self->error_handler_) {
//      self->error_handler_(self.get(), event);
//    }
//    // Should the parent automatically closes when an error occurs.
//  });
//  tls_layer_->onceCloseEvent([weak_self](Transport *transport) -> void {
//    std::shared_ptr<ReliableLayer> self(weak_self.lock());
//    self->close();
//  });
//  tls_layer_->onDataEvent([weak_self](Transport* transport, DataEvent& event) -> void {
//    std::shared_ptr<ReliableLayer> self(weak_self.lock());
//    self->processInboundKeyMethod(event.data.get(), event.length);
//  });
//}
//
//void ReliableLayer::postHandshaked() {
//  state_ = kEstablishedState;
//  logger_->logf(Logger::kLogDebug, "OpenSslTls: handshaked");
//  if (connect_handler_) {
//    connect_handler_(this);
//  }
//}
//
//void ReliableLayer::sendAckV1(int packet_id_count, uint32_t *packet_ids) {
//  protocol::reliable::AckV1Payload ack_payload{protocol::reliable::P_ACK_V1};
//  ack_payload.setAckPacketIdArrayLength(packet_id_count);
//  for (int i = 0; i < packet_id_count; i++) {
//    ack_payload.ackPacketIdArray()[i] = packet_ids[i];
//  }
//  initAckV1PayloadToSend(&ack_payload);
//  sendSimplePayload(&ack_payload);
//}
//
//void ReliableLayer::writeRawPacket(std::unique_ptr<char[]> data, unsigned int len) {
//  transport_->write(std::move(data), len);
//}
//
//void ReliableLayer::processData(protocol::reliable::OpCode op_code, const unsigned char *op_begin, const unsigned char *raw_payload, int length) {
//  const unsigned char *p = raw_payload;
//  const unsigned char *end = raw_payload + length;
//  bool no_iv = false;
//  auto& crypto_ctx = data_crypto_.inbound;
//  const unsigned char* ad_start;
//  uint32_t packet_id = 0;
//  const unsigned char* tag_ptr = nullptr;
//  int rc;
//
//  dump(p, end - p);
//
//  if (op_code == protocol::reliable::P_DATA_V2)
//  {
//    ad_start = op_begin;
//    p += 3;
//  } else if (op_code == protocol::reliable::P_DATA_V1) {
//    ad_start = raw_payload;
//  }
//
//  /* Combine IV from explicit part from packet and implicit part from context */
//  {
//    uint8_t iv[EVP_MAX_IV_LENGTH] = { 0 };
//    const int iv_len = crypto_ctx.cipher->getIVSize();
//    const size_t packet_iv_len = iv_len - crypto_ctx.implicit_iv.size();
//    memcpy(iv, p, packet_iv_len);
//    memcpy(iv + packet_iv_len, crypto_ctx.implicit_iv.data(), crypto_ctx.implicit_iv.size());
//    printf("DECRYPT IV : ");
//    dump(iv, iv_len);
//    crypto_ctx.cipher->reset(iv);
//  }
//
//  packet_id = protocol::reliable::deserializeUint32(p);
//  p += 4;
//
//  tag_ptr = p;
//  auto tag_size = crypto_ctx.cipher->getTagSize();
//  p += tag_size;
//
//  if (crypto_ctx.cipher->isAEADMode()) {
//    /* feed in tag and the authenticated data */
//    const int ad_size = p - ad_start - tag_size;
//    rc = crypto_ctx.cipher->updateAD(ad_start, ad_size);
//  }
//
//  int block_bytes = crypto_ctx.cipher->getBlockSize();
//
//  std::vector<unsigned char> output_buffer(end - p + block_bytes);
//  int output_bytes = 0;
//  rc = crypto_ctx.cipher->updateData(p, end - p, output_buffer.data(), output_buffer.size());
//  if (rc >= 0) {
//    output_bytes += rc;
//    if (crypto_ctx.cipher->isAEADMode()) {
//      crypto_ctx.cipher->setAEADTag(tag_ptr);
//    }
//    rc = crypto_ctx.cipher->final(output_buffer.data() + rc, output_buffer.size() - rc);
//    if (rc > 0) {
//      output_bytes += rc;
//    }
//  }
//
//  logger_->logf(Logger::kLogDebug, "decrypt: %d, %d", rc, output_bytes);
//  dump(output_buffer.data(), output_bytes);
//}
//
//void ReliableLayer::processInboundKeyMethod(const char* data, int length) {
//  do {
//    int proceed_length;
//
//    server_key_method_.init(true);
//    proceed_length = server_key_method_.deserializeFrom((const unsigned char *) data, length);
//    if (proceed_length < 0) {
//      logger_->logf(Logger::kLogWarn, "processInboundKeyMethod: key_method parse failed: %d", proceed_length);
//      state_ = kInitialState;
//      break;
//    }
//
//    if (!server_data_channel_options_.deserialize(server_key_method_.optionsString())) {
//      logger_->logf(Logger::kLogWarn, "processInboundKeyMethod: option_string parse failed: %d", proceed_length);
//      state_ = kInitialState;
//      break;
//    }
//
//    logger_->logf(Logger::kLogDebug, "server side option_string: %s", server_key_method_.optionsString().c_str());
//  } while (0);
//
//  if (protocol_config_.is_tls) {
//    server_data_channel_options_.cipher = "AES-256-GCM";
//    server_data_channel_options_.auth = "[null-digest]";
//  }
//
//  state_ = kGotKeyState;
//  sessionProcess();
//}
//
//
//void ReliableLayer::sessionProcess() {
//  bool server_mode = false;
//
//  if (state_ == kInitialState) {
//    sendControlHardResetClientV2();
//    state_ = kPreStartState;
//  }
//
//  if (state_ == kStartState && !server_mode) {
//    protocol::control::DataChannelOptions& data_channel_options = client_data_channel_options_;
//
//    data_channel_options.version = "V4";
//    data_channel_options.key_method = 2;
//    data_channel_options.dev_type = "tun";
//    data_channel_options.link_mtu = 1543;
//    data_channel_options.tun_mtu = 1500;
//    if (protocol_config_.is_tcp) {
//      data_channel_options.proto = "tcp";
//    } else {
//      data_channel_options.proto = "udp";
//    }
//    data_channel_options.auth = "none";
//    data_channel_options.key_size = 256;
//    data_channel_options.cipher = "AES-256-GCM";
//    data_channel_options.tls_direction = server_mode ? protocol::control::kTlsDirectionClient : protocol::control::kTlsDirectionServer;
//
//    std::unique_ptr<char[]> raw_packet;
//    client_key_method_.init(false);
//    client_key_method_.setOptionString(data_channel_options.serialize());
//    raw_packet.reset(new char[client_key_method_.getSerializedSize()]);
//    client_key_method_.serializeTo((unsigned char *) raw_packet.get());
//
//    logger_->logf(Logger::kLogDebug, "doKeyShare: %s", client_key_method_.optionsString().c_str());
//    write(std::move(raw_packet), client_key_method_.getSerializedSize());
//    state_ = kSentKeyState;
//  }
//
//  if (state_ == kGotKeyState) {
//    key2 temp_key2;
//    generateKeyExpansion(&temp_key2);
//    initKeyContexts(&data_crypto_, &temp_key2, false, "Data Channel");
//    state_ = kEstablishedState;
//    logger_->logf(Logger::kLogDebug, "ReliableLayer: kEstablishedState");
//  }
//}
//
//void ReliableLayer::initKeyContexts(BiCryptoContext* crypto_context, key2* pkey2, bool server_mode, const char* key_name) {
//  char label[256];
//  key* inbound_key = &pkey2->keys[server_mode ? kClientKey : kServerKey];
//  key* outbound_key = &pkey2->keys[server_mode ? kServerKey : kClientKey];
//  auto& inbound_data_channel_options = server_mode ? client_data_channel_options_ : server_data_channel_options_;
//  auto& outbound_data_channel_options = server_mode ? server_data_channel_options_ : client_data_channel_options_;
//
//  auto inbound_cipher_algorithm = crypto_provider_->getCipherAlgorithm(inbound_data_channel_options.cipher);
//  auto inbound_auth_algorithm = crypto_provider_->getAuthAlgorithm(inbound_data_channel_options.auth);
//  auto outbound_cipher_algorithm = crypto_provider_->getCipherAlgorithm(outbound_data_channel_options.cipher);
//  auto outbound_auth_algorithm = crypto_provider_->getAuthAlgorithm(outbound_data_channel_options.auth);
//
//  crypto_context->inbound.cipher = inbound_cipher_algorithm->createDecipher();
//  crypto_context->inbound.hmac = inbound_auth_algorithm->create();
//  crypto_context->outbound.cipher = outbound_cipher_algorithm->createEncipher();
//  crypto_context->outbound.hmac = outbound_auth_algorithm->create();
//
//  snprintf(label, sizeof(label), "Outgoing %s", key_name);
//  crypto_context->outbound.cipher->init(outbound_key->cipher);
//  printf("outgoing key : "); dump(outbound_key->cipher, sizeof(outbound_key->cipher));
//  crypto_context->outbound.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
//  if (crypto_context->outbound.hmac) {
//    crypto_context->outbound.hmac->init(outbound_key->hmac);
//  }
//  crypto_context->outbound.setImplicitIV(outbound_key->hmac, MAX_HMAC_KEY_LENGTH);
//
//  snprintf(label, sizeof(label), "Incoming %s", key_name);
//  printf("Incoming key : "); dump(inbound_key->cipher, sizeof(inbound_key->cipher));
//  crypto_context->inbound.cipher->init(inbound_key->cipher);
//  crypto_context->inbound.cipher->setTagSize(OPENVPN_AEAD_TAG_LENGTH);
//  if (crypto_context->inbound.hmac) {
//    crypto_context->inbound.hmac->init(inbound_key->hmac);
//  }
//  crypto_context->inbound.setImplicitIV(inbound_key->hmac, MAX_HMAC_KEY_LENGTH);
//}


} // namespace transport
} // namespace ovpnc
