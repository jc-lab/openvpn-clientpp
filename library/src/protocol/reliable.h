/**
 * @file	reliable.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
/*
 * References:
 * - https://openvpn.net/community-resources/openvpn-protocol/
 * - https://github.com/corelight/zeek-openvpn/blob/v0.0.2/src/openvpn-defs.pac
 */

#ifndef OVPNC_SRC_PROTOCOL_RELIABLE_H_
#define OVPNC_SRC_PROTOCOL_RELIABLE_H_

#include <stdint.h>

#include <memory>
#include <vector>
#include <list>

#include "base.h"

namespace ovpnc {
namespace protocol {
namespace reliable {

enum OpCode {
  P_NONE = 0,

  /**
   * Key method 1, initial key from client, forget previous state.
   */
  P_CONTROL_HARD_RESET_CLIENT_V1 = 1,

  /**
   * Key method 1, initial key from server, forget previous state.
   */
  P_CONTROL_HARD_RESET_SERVER_V1 = 2,

  /**
   * New key, with a graceful transition
   * from old to new key in the sense that a transition window
   * exists where both the old or new key_id can be used.  OpenVPN
   * uses two different forms of key_id.  The first form is 64 bits
   * and is used for all P_CONTROL messages.  P_DATA messages on the
   * other hand use a shortened key_id of 3 bits for efficiency
   * reasons since the vast majority of OpenVPN packets in an
   * active tunnel will be P_DATA messages.  The 64 bit form
   * is referred to as a session_id, while the 3 bit form is
   * referred to as a key_id.
   */
  P_CONTROL_SOFT_RESET_V1 = 3,

  /**
   * Control channel packet (usually TLS ciphertext).
   */
  P_CONTROL_V1 = 4,

  /**
   * Acknowledgement for P_CONTROL packets received.
   */
  P_ACK_V1 = 5,

  /**
   * Data channel packet containing actual
   * tunnel data
   */
  P_DATA_V1 = 6,
  P_DATA_V2 = 9,

  /**
   * Key method 2, initial key from client,
   * forget previous state.
   */
  P_CONTROL_HARD_RESET_CLIENT_V2 = 7,
  /**
   * Key method 2, initial key from server,
   * forget previous state.
   */
  P_CONTROL_HARD_RESET_SERVER_V2 = 8,

  /**
   * indicates key_method >= 2 and
   * client-specific tls-crypt key
   *
   * initial key from client,
   * forget previous state
   */
  P_CONTROL_HARD_RESET_CLIENT_V3 = 10
};

class ProtocolUtil {
 public:
  static const char *opcodeName(OpCode code);
};

struct ProtocolTransportConfig {
  bool is_tcp;
  bool is_tls;
};

class ReliablePayload : public PayloadBase {
 private:
  OpCode op_code_;

 public:
  ReliablePayload(OpCode op_code) : op_code_(op_code) {}
  virtual OpCode getOpCode() const {
    return op_code_;
  }
};

/**
 * prepare -> getAppendDataBuffer -> setAppendDataSize() -> write() -> getPacketLength()
 */
class PacketWriter {
 protected:
  const ProtocolTransportConfig *config_;
  int header_size_;
  int ensured_append_data_size_;
  int append_data_size_;
  int payload_size_;
  const ReliablePayload *payload_;

 public:
  PacketWriter(const ProtocolTransportConfig *config) :
      config_(config),
      header_size_(0),
      ensured_append_data_size_(0),
      append_data_size_(0),
      payload_size_(0) {}

  void prepare(const ReliablePayload *payload, int append_data_size = 0);

  unsigned char *getAppendDataBuffer() const {
    return getPacketBuffer() + header_size_ + payload_size_;
  }

  /**
   * change append data size
   *
   * @param append_data_size MUST less than or equal to the append_data_size set during prepare.
   */
  void setAppendDataSize(int append_data_size) {
    if (ensured_append_data_size_ < append_data_size) return;
    append_data_size_ = append_data_size;
  }

  int getPacketLength() const {
    return header_size_ + payload_size_ + append_data_size_;
  }

  /**
   * write header and payload
   */
  void write(uint8_t key_id);

  virtual void allocatePacketBuffer(int size) = 0;
  virtual unsigned char *getPacketBuffer() const = 0;
};

class UniqueCharArrPacketWriter : public PacketWriter {
 public:
  std::unique_ptr<char[]> buffer;

  UniqueCharArrPacketWriter(const ProtocolTransportConfig *config);
  void allocatePacketBuffer(int size) override;
  unsigned char *getPacketBuffer() const override;
};

class HMACInfoPayload : public ReliablePayload {
 public:
  uint8_t hmac[20];
  uint32_t packet_id;
  uint8_t net_time[4];

 public:
  HMACInfoPayload() : ReliablePayload(P_NONE) {}
  OpCode getOpCode() const override {
    return P_NONE;
  }
  int getSerializedSize() const override {
    return 28;
  }
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

class ControlV1Payload : public ReliablePayload {
 private:
  bool hmac_present_;

  uint8_t session_id_[8];
  /**
   * Optional (hmac_present)
   */
  HMACInfoPayload hmac_;
  uint8_t ack_packet_id_array_len_;

  /**
   * size = packet_id_array_len
   */
  std::vector<uint32_t> ack_packet_id_array_;

  /**
   * Optional (remote_session)
   */
  unsigned char remote_session_id_[8];

  uint32_t packet_id_;

  // ssl_data
 public:
  ControlV1Payload(OpCode op_code);

  void setSessionId(const unsigned char *session_id);

  const unsigned char *sessionId() const {
    return session_id_;
  }

  void setAckPacketIdArrayLength(uint8_t length) {
    ack_packet_id_array_len_ = length;
    ack_packet_id_array_.resize(length);
  }

  uint8_t ackPacketIdArrayLength() const {
    return ack_packet_id_array_len_;
  }

  std::vector<uint32_t> &ackPacketIdArray() {
    return ack_packet_id_array_;
  }

  void clearHmac() {
    hmac_present_ = false;
  }

  void setHmac(const HMACInfoPayload &hmac) {
    hmac_present_ = true;
    hmac_ = hmac;
  }

  void setHmacPresent(bool hmac_present) {
    hmac_present_ = hmac_present;
  }

  const HMACInfoPayload &hmac() const {
    return hmac_;
  }

  bool hasRemoteSessionId() const {
    return ack_packet_id_array_len_ > 0;
  }

  void setRemoteSessionId(const unsigned char *remote_session_id);

  const unsigned char *remoteSessionId() const {
    return remote_session_id_;
  }

  void setPacketId(uint32_t packet_id) {
    packet_id_ = packet_id;
  }

  uint32_t packetId() const {
    return packet_id_;
  }

  int getSerializedSize() const override;
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

class AckV1Payload : public ReliablePayload {
 private:
  bool hmac_present_;

  uint8_t session_id_[8];
  /**
   * Optional (hmac_present)
   */
  HMACInfoPayload hmac_;
  uint8_t ack_packet_id_array_len_;

  /**
   * size = packet_id_array_len
   */
  std::vector<uint32_t> ack_packet_id_array_;

  /**
   * Optional (remote_session)
   */
  unsigned char remote_session_id_[8];
 public:
  AckV1Payload(OpCode op_code);

  void setSessionId(const unsigned char *session_id);

  const unsigned char *sessionId() const {
    return session_id_;
  }

  void setAckPacketIdArrayLength(uint8_t length) {
    ack_packet_id_array_len_ = length;
    ack_packet_id_array_.resize(length);
  }

  uint8_t ackPacketIdArrayLength() const {
    return ack_packet_id_array_len_;
  }

  std::vector<uint32_t> &ackPacketIdArray() {
    return ack_packet_id_array_;
  }

  void clearHmac() {
    hmac_present_ = false;
  }

  void setHmac(const HMACInfoPayload &hmac) {
    hmac_present_ = true;
    hmac_ = hmac;
  }

  void setHmacPresent(bool hmac_present) {
    hmac_present_ = hmac_present;
  }

  const HMACInfoPayload &hmac() const {
    return hmac_;
  }

  bool hasRemoteSessionId() const {
    return ack_packet_id_array_len_ > 0;
  }

  void setRemoteSessionId(const unsigned char *remote_session_id);

  const unsigned char *remoteSessionId() const {
    return remote_session_id_;
  }

  int getSerializedSize() const override;
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

class DataV1Payload : public ReliablePayload {
 public:
  // payload

 public:
  DataV1Payload(OpCode op_code);

  int getSerializedSize() const override;
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

class DataV2Payload : public ReliablePayload {
 public:
  uint8_t peer_id[3];
  // payload

 public:
  DataV2Payload(OpCode op_code);

  int getSerializedSize() const override;
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

} // namespace reliable
} // namespace protocol
} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_RELIABLE_H_
