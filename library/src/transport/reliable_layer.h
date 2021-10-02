/**
 * @file	reliable_layer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-10
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_
#define OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_

#include <stdint.h>
#include <memory>
#include <mutex>

#include <jcu-unio/buffer.h>
#include <jcu-unio/timer.h>
#include <jcu-unio/net/socket.h>
#include <jcu-unio/net/ssl_socket.h>

#include <ovpnc/vpn_config.h>
#include <ovpnc/push_options.h>
#include <ovpnc/crypto/provider.h>
#include <ovpnc/crypto/cipher.h>
#include <ovpnc/crypto/auth.h>

#include "../protocol/reliable.h"
#include "../protocol/control.h"

#define    OPENVPN_AEAD_TAG_LENGTH   16
#define    OPENVPN_MAX_CIPHER_BLOCK_SIZE   32
#define    OPENVPN_MAX_HMAC_SIZE   64
#define    MAX_CIPHER_KEY_LENGTH   64
#define    MAX_HMAC_KEY_LENGTH   64

namespace ovpnc {
namespace transport {

typedef uint32_t packet_id_t;

class Multiplexer;

class ReliableLayer : public jcu::unio::Resource, public jcu::unio::Emitter {
 public:
  template<class T>
  using CompletionOnceCallback = std::function<void(T &event)>;

  enum Mode {
    kClientMode,
    kServerMode,
  };

  enum UnwrapResult {
    kUnwrapOk,
    kUnwrapFailed,
    kUnwrapData
  };

  class LazyAckContext {
   protected:
    bool sent_;
    std::vector<uint32_t> ack_packet_ids_;

   public:
    LazyAckContext() {
      sent_ = false;
    }

    void setSent() {
      sent_ = true;
    }

    bool isSent() const {
      return sent_;
    }

    const std::vector<uint32_t> &getAckPacketIds() const {
      return ack_packet_ids_;
    }

    void addPacketId(uint32_t packet_id) {
      ack_packet_ids_.emplace_back(packet_id);
    }
  };

  struct LastSendPacket {
    bool active;
    uint8_t op_code;
    uint32_t packet_id;
    std::shared_ptr<jcu::unio::Buffer> buffer;
    std::shared_ptr<jcu::unio::Timer> timer;
    int retries;

    LastSendPacket() {
      clear();
    }
    void clear() {
      active = false;
      op_code = 0;
      retries = 0;
      if (timer) {
        timer->close();
      }
      timer.reset();
      buffer.reset();
    }
  };

  struct CryptoContext {
    std::unique_ptr<crypto::CipherContext> cipher;
    std::unique_ptr<crypto::AuthContext> hmac;
    std::vector<unsigned char> implicit_iv;

    void setImplicitIV(const unsigned char *key, int length) {
      implicit_iv.clear();
      if (cipher->isAEADMode()) {
        size_t impl_iv_len = cipher->getIVSize() - sizeof(packet_id_t);
        implicit_iv.insert(implicit_iv.end(), key, key + impl_iv_len);
      }
    }
  };

  /**
   * Container for unidirectional cipher and HMAC %key material.
   * @ingroup control_processor
   */
  struct key {
    uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
    /**< %Key material for cipher operations. */
    uint8_t hmac[MAX_HMAC_KEY_LENGTH];
    /**< %Key material for HMAC operations. */
  };

  enum Key2Index {
    kClientKey = 0,
    kServerKey = 1,
  };

  /**
   * Container for bidirectional cipher and HMAC %key material.
   * @ingroup control_processor
   */
  struct key2 {
    /**
     * The number of \c key objects stored
     * in the \c key2.keys array.
     */
    int n;
    /**
     * Two unidirectional sets of %key material
     */
    struct key keys[2];
  };

  struct SessionContext {
    uint8_t session_id[8];

    //region crypto_options
    /**
     * local: decryptor
     * peer : encryptor
     */

    /**
     * last received packet_id
     */
    packet_id_t packet_id;
    /**
     * last sent packet_id
     */
    packet_id_t data_packet_id;
    //endregion

    protocol::control::KeyMethod2 key_method;
    protocol::control::DataChannelOptions data_channel_options;
    SessionContext();
  };

  enum KeyStatus {
    kKeyStateInitial,
    kKeyStatePreStart,
    kKeyStateStart,
    kKeyStateSent,
    kKeyStateEstablished,
  };

  struct KeyState {
    KeyStatus state;
    int key_id;
    CryptoContext inbound_crypto;
    CryptoContext outbound_crypto;
    SessionContext local;
    SessionContext peer;
  };

 private:
  class SSLSocketMiddleware;

  std::mutex init_mtx_;
  std::weak_ptr<ReliableLayer> self_;

  jcu::unio::BasicParams basic_params_;
  VPNConfig vpn_config_;

  std::shared_ptr<crypto::Random> random_;
  std::shared_ptr<Multiplexer> multiplexer_;

  std::shared_ptr<jcu::unio::SSLSocket> ssl_socket_;
  std::shared_ptr<SSLSocketMiddleware> ssl_socket_middleware_;
  ReliableLayer::LazyAckContext *lazy_ack_context_;

  Mode mode_;
  bool peer_inited_;

  KeyState key_state_;
  protocol::reliable::OpCode data_opcode_;
  std::shared_ptr<jcu::unio::Timer> push_request_timer_;

  std::shared_ptr<jcu::unio::Buffer> send_message_buffer_;
  std::list<LastSendPacket> send_packets_;

  PushOptions last_push_reply_;
  std::function<void(const PushOptions& options)> push_reply_callback_;

  void handleReceivedAcks(const protocol::reliable::SessionReliablePayload &payload);
  bool preprocessPayload(const protocol::reliable::SessionReliablePayload &payload);

  void emitPushReply(const char* data);

 protected:
  std::shared_ptr<jcu::unio::Resource> sharedAsResource() override;
  void _init();
  std::mutex &getInitMutex() override {
    return init_mtx_;
  }
  void invokeInitEventCallback(
      std::function<void(jcu::unio::InitEvent & , Resource &)> &&callback, jcu::unio::InitEvent &event
  ) override;

 public:
  static std::shared_ptr<ReliableLayer> create(
      const jcu::unio::BasicParams& basic_params
  );

  ReliableLayer(
      const jcu::unio::BasicParams& basic_params
  );

 public:
  bool isHandshaked() const;

  SessionContext &getClientSession();
  SessionContext &getServerSession();
  const SessionContext &getClientSession() const;
  const SessionContext &getServerSession() const;

  void init(
      std::shared_ptr<Multiplexer> multiplexer,
      std::shared_ptr<jcu::unio::Buffer> send_message_buffer
  );
  void start(const VPNConfig& vpn_config);

  void close();

  /**
   * new key_id
   * need P_CONTROL_SOFT_RESET_V1 after the call
   */
  void keyStateInit();

  uint8_t getKeyId() const;
  uint32_t nextPacketId();

  UnwrapResult unwrap(
      ReliableLayer::LazyAckContext &ack_context,
      protocol::reliable::OpCode opcode,
      uint8_t key_id,
      const unsigned char *data,
      size_t length,
      jcu::unio::Buffer *output
  );
  bool wrapData(
      jcu::unio::Buffer *input,
      jcu::unio::Buffer *output,
      uint8_t *popcode
  );

  void doNextOperationAndSendLazyAcks(
      ReliableLayer::LazyAckContext *ack_context
  );

  bool handleControlPayload(
      ReliableLayer::LazyAckContext &ack_context,
      protocol::reliable::OpCode op_code,
      uint8_t key_id,
      const unsigned char *data,
      size_t length
  );
  bool handleAckV1Payload(
      ReliableLayer::LazyAckContext &ack_context,
      protocol::reliable::OpCode op_code,
      uint8_t key_id,
      const unsigned char *data,
      size_t length
  );

  void handleTlsPayload(jcu::unio::Buffer *buffer);

  void sendControlHardResetClientV2();

  void prepareSessionPayload(protocol::reliable::SessionReliablePayload &payload);
  void sendAckV1(
      int packet_id_count,
      const uint32_t *packet_ids,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback);

  void sendWithRetry(
      uint8_t op_code,
      uint32_t packet_id,
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback);

  void onPushReply(std::function<void(const PushOptions& options)> callback);

 private:
  bool openvpn_PRF(
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
  );
  bool generateKeyExpansion(key2 *pkey2);
  bool generateKeyExpansionOvpnPRF(key2 *pkey2);
  void initKeyContexts(KeyState &key_state, key2 *pkey2, const char *key_name);

  void sendKeyState();
  void sendPushRequest();
  void startPushRequest();

  UnwrapResult unwrapDataPayload(
      protocol::reliable::OpCode opcode,
      uint8_t key_id,
      const unsigned char *data,
      size_t length,
      jcu::unio::Buffer *output
  );
};

} // namespace transport
} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_
