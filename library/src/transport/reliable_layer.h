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
#include <vector>

#include <ovpnc/tls_provider.h>
#include <ovpnc/crypto/cipher.h>
#include <ovpnc/crypto/auth.h>
#include <ovpnc/crypto/provider.h>

#include "../log.h"
#include "transport.h"

#include "../protocol/reliable.h"
#include "../protocol/control.h"
#include "tls_layer.h"

#define MAX_CIPHER_KEY_LENGTH 64
#define MAX_HMAC_KEY_LENGTH 64
#define OPENVPN_AEAD_TAG_LENGTH 16

namespace ovpnc {
namespace transport {

typedef uint32_t packet_id_t;

struct CryptoContext {
  std::unique_ptr<crypto::CipherContext> cipher;
  std::unique_ptr<crypto::AuthContext> hmac;
  std::vector<unsigned char> implicit_iv;

  void setImplicitIV(const unsigned char* key, int length) {
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
struct key
{
  uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
  /**< %Key material for cipher operations. */
  uint8_t hmac[MAX_HMAC_KEY_LENGTH];
  /**< %Key material for HMAC operations. */
};
/**
 * Container for bidirectional cipher and HMAC %key material.
 * @ingroup control_processor
 */
struct key2
{
  int n;
  struct key keys[2];
};

enum Key2Index {
  kClientKey = 0,
  kServerKey = 1,
};

struct BiCryptoContext {
  CryptoContext inbound; // encrypt
  CryptoContext outbound; // decrypt
};

class ReliableLayer : public Transport {
 public:
  enum State {
    /**
     * Error State
     */
    kErrorState = -1,
    kNotStarted = 0,
    /**
     * Transport Connected
     */
    kInitialState,
    /**
     * Waiting for the remote OpenVPN peer
     * to acknowledge during the initial
     * three-way handshake.
     */
    kPreStartState,
    /**
     * Three-way handshake is complete,
     * start of key exchange.
     */
    kStartState,
    /**
     * Local OpenVPN process has sent its
     * part of the key material.
     */
    kSentKeyState,
    /**
     * Local OpenVPN process has received
     * the remote's part of the key
     * material.
     */
    kGotKeyState,
    /**
     * Operational \c key_state state
     * immediately after negotiation has
     * completed while still within the
     * handshake window.
     */
    kEstablishedState,
  };

  typedef std::function<std::shared_ptr<TlsLayer>(std::shared_ptr<ReliableLayer> self)> ReliableLayerTlsLayerSupplier_t;

 private:
  std::weak_ptr<ReliableLayer> self_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<Transport> transport_;
  ReliableLayerTlsLayerSupplier_t tls_layer_supplier_;
  std::shared_ptr<crypto::Provider> crypto_provider_;
  bool cleanup_;

  ConnectEventHandler_t connect_handler_;
  CloseEventHandler_t close_handler_;
  ErrorEventHandler_t error_handler_;
  CleanupHandler_t cleanup_handler_;
  DataEventHandler_t data_handler_;

  State state_;
  std::shared_ptr<TlsLayer> tls_layer_;

  packet_id_t client_packet_id_;
  packet_id_t server_packet_id_;
  unsigned char client_session_id_[8];
  unsigned char server_session_id_[8];
  protocol::control::KeyMethod2 client_key_method_;
  protocol::control::DataChannelOptions client_data_channel_options_;
  protocol::control::KeyMethod2 server_key_method_;
  protocol::control::DataChannelOptions server_data_channel_options_;
  std::vector<unsigned char> recv_buffer_;
  int recv_position_;

  BiCryptoContext data_crypto_;

  ReliableLayer(
      std::shared_ptr<Logger> logger,
      std::shared_ptr<Transport> parent,
      ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
      std::shared_ptr<crypto::Provider> crypto_provider
      );

  void sessionInit();
  void sendControlHardResetClientV2();

  void sessionProcess();

  void processInbound(Transport::DataEvent &event);
  void processPacketInbound(const unsigned char *buffer, int length);
  void processControlHardResetServerV2(
      protocol::reliable::OpCode op_code,
      const unsigned char *raw_payload,
      int length
  ); // P_CONTROL_HARD_RESET_SERVER_V2
  void processControlV1(
      protocol::reliable::OpCode op_code,
      const unsigned char *raw_payload,
      int length
  ); // P_CONTROL_V1
  void processData(
      protocol::reliable::OpCode op_code,
      const unsigned char *op_begin,
      const unsigned char *raw_payload,
      int length
  ); // P_DATA_V1

  void sendSimplePayload(const protocol::reliable::ReliablePayload *payload);

  void sendAckV1(int packet_id_count, uint32_t *packet_ids);

  void cleanup();

  bool openvpn_PRF(
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
  );

  void processInboundKeyMethod(const char* data, int length);

 private:
  void tlsInit();
  void postHandshaked();

  bool generateKeyExpansion(key2* pkey2);
  bool generateKeyExpansionOvpnPRF(key2* pkey2);

  void initKeyContexts(BiCryptoContext* crypto_context, key2* pkey2, bool server_mode, const char* key_name);

 public:
  ~ReliableLayer();

  static std::shared_ptr<ReliableLayer> create(
      std::shared_ptr<Logger> logger,
      std::shared_ptr<Transport> parent,
      ReliableLayerTlsLayerSupplier_t tls_layer_supplier,
      std::shared_ptr<crypto::Provider> crypto_provider
      );

  std::shared_ptr<uvw::Loop> getLoop() override;

  void connect(const sockaddr *addr) override;
  void connect(const uvw::Addr &addr) override;
  void read() override;
  void write(std::unique_ptr<char[]> data, unsigned int len) override;
  void onceConnectEvent(const ConnectEventHandler_t &handler) override;
  void onDataEvent(const DataEventHandler_t &handler) override;
  void onceCloseEvent(const CloseEventHandler_t &handler) override;
  void onceErrorEvent(const ErrorEventHandler_t &handler) override;
  void onceCleanupEvent(const CleanupHandler_t &handler) override;
  void shutdown() override;
  void close() override;

  void initControlV1PayloadToSend(protocol::reliable::ControlV1Payload *payload);
  void initAckV1PayloadToSend(protocol::reliable::AckV1Payload *payload);
  void writeRawPacket(std::unique_ptr<char[]> data, unsigned int len);
};

} // namespace transport
} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_
