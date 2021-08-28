/**
 * @file	reliable.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-07
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <string>
#include <cstring>

#include "reliable.h"

namespace ovpnc {
namespace protocol {
namespace reliable {

void serializeUint32(unsigned char *buffer, uint32_t value) {
  buffer[0] = (uint8_t) (value >> 24);
  buffer[1] = (uint8_t) (value >> 16);
  buffer[2] = (uint8_t) (value >> 8);
  buffer[3] = (uint8_t) (value);
}

uint32_t deserializeUint32(const unsigned char *buffer) {
  uint32_t value = 0;
  value |= ((uint32_t) (*(buffer++))) << 24;
  value |= ((uint32_t) (*(buffer++))) << 16;
  value |= ((uint32_t) (*(buffer++))) << 8;
  value |= ((uint32_t) (*(buffer++)));
  return value;
}

const char *ProtocolUtil::opcodeName(OpCode code) {
  switch (code) {
    case P_CONTROL_HARD_RESET_CLIENT_V1:return "P_CONTROL_HARD_RESET_CLIENT_V1";
    case P_CONTROL_HARD_RESET_SERVER_V1:return "P_CONTROL_HARD_RESET_SERVER_V1";
    case P_CONTROL_HARD_RESET_CLIENT_V2:return "P_CONTROL_HARD_RESET_CLIENT_V2";
    case P_CONTROL_HARD_RESET_SERVER_V2:return "P_CONTROL_HARD_RESET_SERVER_V2";
    case P_CONTROL_HARD_RESET_CLIENT_V3:return "P_CONTROL_HARD_RESET_CLIENT_V3";
    case P_CONTROL_SOFT_RESET_V1:return "P_CONTROL_SOFT_RESET_V1";
    case P_CONTROL_V1:return "P_CONTROL_V1";
    case P_ACK_V1:return "P_ACK_V1";
    case P_DATA_V1:return "P_DATA_V1";
    case P_DATA_V2:return "P_DATA_V2";
    default:return "P_Unknown";
  }
}

unsigned char *HMACInfoPayload::serializeTo(unsigned char *buffer) const {
  unsigned char *p = buffer;
  std::memcpy(p, hmac, sizeof(hmac));
  p += sizeof(hmac);
  serializeUint32(p, packet_id);
  p += 4;
  std::memcpy(p, net_time, sizeof(net_time));
  p += sizeof(net_time);
  return p;
}

int HMACInfoPayload::deserializeFrom(const unsigned char *buffer, int length) {
  const unsigned char *p = buffer;
  if (length != getSerializedSize()) return -1;
  std::memcpy(hmac, p, sizeof(hmac));
  p += sizeof(hmac);
  packet_id = deserializeUint32(p);
  p += 4;
  std::memcpy(net_time, p, sizeof(net_time));
  p += sizeof(net_time);
  return getSerializedSize();
}

ControlV1Payload::ControlV1Payload(OpCode op_code) :
    ReliablePayload(op_code),
    hmac_present_(false),
    hmac_{},
    ack_packet_id_array_len_(0),
    packet_id_(0) {
}

void ControlV1Payload::setRemoteSessionId(const unsigned char *remote_session_id) {
  std::memcpy(remote_session_id_, remote_session_id, sizeof(remote_session_id_));
}

int ControlV1Payload::getSerializedSize() const {
  int size = 8; // session_id
  if (hmac_present_) {
    size += hmac_.getSerializedSize();
  }
  size += 1; // packet_id_array_len
  size += 4 * ack_packet_id_array_len_; // packet_id_array
  if (hasRemoteSessionId()) {
    size += 8; // remote_session_id
  }
  size += 4; // packet_id
  return size;
}

unsigned char *ControlV1Payload::serializeTo(unsigned char *buffer) const {
  unsigned char *p = buffer;
  memcpy(p, session_id_, sizeof(session_id_));
  p += sizeof(session_id_);
  if (hmac_present_) {
    hmac_.serializeTo(p);
    p += hmac_.getSerializedSize();
  }
  *(p++) = ack_packet_id_array_len_;
  for (int i = 0; i < ack_packet_id_array_len_; i++) {
    serializeUint32(p, ack_packet_id_array_[i]);
    p += 4;
  }
  if (hasRemoteSessionId()) {
    std::memcpy(p, remote_session_id_, sizeof(remote_session_id_));
    p += sizeof(remote_session_id_);
  }
  serializeUint32(p, packet_id_);
  p += 4;
  return p;
}

void ControlV1Payload::setSessionId(const unsigned char *session_id) {
  std::memcpy(session_id_, session_id, sizeof(session_id_));
}

int ControlV1Payload::deserializeFrom(const unsigned char *buffer, int length) {
  const unsigned char *p = buffer;
  const unsigned char *end = buffer + length;
  if ((end - p) < sizeof(session_id_)) return false;
  memcpy(session_id_, p, sizeof(session_id_));
  p += sizeof(session_id_);
  if (hmac_present_) {
    if ((end - p) < hmac_.getSerializedSize()) return false;
    hmac_.deserializeFrom(p, hmac_.getSerializedSize());
    p += hmac_.getSerializedSize();
  }
  if ((end - p) < 1) return false;
  setAckPacketIdArrayLength(*(p++));
  if ((end - p) < (4 * ack_packet_id_array_len_)) return false;
  for (int i = 0; i < ack_packet_id_array_len_; i++) {
    ack_packet_id_array_[i] = deserializeUint32(p);
    p += 4;
  }
  if (hasRemoteSessionId()) {
    if ((end - p) < sizeof(remote_session_id_)) return false;
    std::memcpy(remote_session_id_, p, sizeof(remote_session_id_));
    p += sizeof(remote_session_id_);
  }
  if ((end - p) < 4) return false;
  packet_id_ = deserializeUint32(p);
  p += 4;
  return (p - buffer);
}

AckV1Payload::AckV1Payload(OpCode op_code) :
    ReliablePayload(op_code),
    hmac_present_(false),
    hmac_{},
    ack_packet_id_array_len_(0) {
}

int AckV1Payload::getSerializedSize() const {
  int size = 8; // session_id
  if (hmac_present_) {
    size += hmac_.getSerializedSize();
  }
  size += 1; // packet_id_array_len
  size += 4 * ack_packet_id_array_len_; // packet_id_array
  size += 8; // remote_session_id
  return size;
}

unsigned char *AckV1Payload::serializeTo(unsigned char *buffer) const {
  unsigned char *p = buffer;
  memcpy(p, session_id_, sizeof(session_id_));
  p += sizeof(session_id_);
  if (hmac_present_) {
    hmac_.serializeTo(p);
    p += hmac_.getSerializedSize();
  }
  *(p++) = ack_packet_id_array_len_;
  for (int i = 0; i < ack_packet_id_array_len_; i++) {
    serializeUint32(p, ack_packet_id_array_[i]);
    p += 4;
  }
  memcpy(p, remote_session_id_, sizeof(remote_session_id_));
  p += sizeof(remote_session_id_);
  return p;
}
int AckV1Payload::deserializeFrom(const unsigned char *buffer, int length) {
  return -1;
}

void AckV1Payload::setSessionId(const unsigned char *session_id) {
  std::memcpy(session_id_, session_id, sizeof(session_id_));
}

void AckV1Payload::setRemoteSessionId(const unsigned char *remote_session_id) {
  std::memcpy(remote_session_id_, remote_session_id, sizeof(remote_session_id_));
}

DataV1Payload::DataV1Payload(OpCode op_code) :
    ReliablePayload(op_code) {}

int DataV1Payload::getSerializedSize() const {
  return 0;
}

unsigned char *DataV1Payload::serializeTo(unsigned char *buffer) const {
  return buffer;
}
int DataV1Payload::deserializeFrom(const unsigned char *buffer, int length) {
  return -1;
}

DataV2Payload::DataV2Payload(OpCode op_code) :
    ReliablePayload(op_code) {}

int DataV2Payload::getSerializedSize() const {
  return 3;
}

unsigned char *DataV2Payload::serializeTo(unsigned char *buffer) const {
  return buffer + 3;
}

int DataV2Payload::deserializeFrom(const unsigned char *buffer, int length) {
  return -1;
}

void UniqueCharArrPacketWriter::allocatePacketBuffer(int size) {
  this->buffer.reset(new char[size]);
}

unsigned char *UniqueCharArrPacketWriter::getPacketBuffer() const {
  return (unsigned char *) this->buffer.get();
}

UniqueCharArrPacketWriter::UniqueCharArrPacketWriter(const ProtocolTransportConfig *config) :
    PacketWriter(config) {
}

void PacketWriter::write(uint8_t key_id) {
  unsigned char *p = getPacketBuffer();
  int packet_size = payload_size_ + append_data_size_;
  if (config_->is_tcp) {
    // packet size
    *(p++) = (unsigned char) ((packet_size >> 8) & 0xff);
    *(p++) = (unsigned char) ((packet_size) & 0xff);
  }
  if (config_->is_tls) {
    // op code
    *(p++) = (unsigned char) (payload_->getOpCode() << 3) | (key_id & 0x7);
  }
  payload_->serializeTo(p);
}

void PacketWriter::prepare(const ReliablePayload *payload, int append_data_size) {
  header_size_ = 0;
  ensured_append_data_size_ = append_data_size;
  append_data_size_ = append_data_size;
  payload_size_ = payload->getSerializedSize();
  payload_ = payload;

  if (config_->is_tcp) {
    // packet size
    header_size_ += 2;
  }
  if (config_->is_tls) {
    // op code
    payload_size_ += 1;
  }
  allocatePacketBuffer(getPacketLength());
}

} // namespace reliable
} // namespace protocol
} // namespace ovpnc
