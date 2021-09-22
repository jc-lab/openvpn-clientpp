/**
 * @file	rw_buffer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-22
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <cstring>

#include "rw_buffer.h"

namespace ovpnc {
namespace transport {

#define UWBUF(buf) ((uint8_t*)buf->data())
#define URBUF(buf) ((const uint8_t*)buf->data())

RWBuffer::RWBuffer(jcu::unio::Buffer *buf) :
    buf_(buf) {
}

void RWBuffer::flip() {
  buf_->flip();
}
unsigned char* RWBuffer::data() {
  if (!buf_) return nullptr;
  return (unsigned char*) buf_->data();
}
size_t RWBuffer::remaining() const {
  return buf_->remaining();
}
bool RWBuffer::skip(int length) {
  if (buf_->remaining() < length) return false;
  buf_->position(buf_->position() + length);
  return true;
}
bool RWBuffer::writeUint8(uint8_t value) {
  if (buf_->remaining() < 1) return false;
  UWBUF(buf_)[0] = (uint8_t) (value);
  buf_->position(buf_->position() + 1);
  return true;
}
bool RWBuffer::writeUint16(uint16_t value) {
  if (buf_->remaining() < 2) return false;
  UWBUF(buf_)[0] = (uint8_t) (value >> 8);
  UWBUF(buf_)[1] = (uint8_t) (value);
  buf_->position(buf_->position() + 2);
  return true;
}
bool RWBuffer::writeUint32(uint32_t value) {
  if (buf_->remaining() < 4) return false;
  UWBUF(buf_)[0] = (uint8_t) (value >> 24);
  UWBUF(buf_)[1] = (uint8_t) (value >> 16);
  UWBUF(buf_)[2] = (uint8_t) (value >> 8);
  UWBUF(buf_)[3] = (uint8_t) (value);
  buf_->position(buf_->position() + 4);
  return true;
}
bool RWBuffer::writeUint64(uint64_t value) {
  if (buf_->remaining() < 8) return false;
  UWBUF(buf_)[0] = (uint8_t) (value >> 56);
  UWBUF(buf_)[1] = (uint8_t) (value >> 48);
  UWBUF(buf_)[2] = (uint8_t) (value >> 40);
  UWBUF(buf_)[3] = (uint8_t) (value >> 32);
  UWBUF(buf_)[4] = (uint8_t) (value >> 24);
  UWBUF(buf_)[5] = (uint8_t) (value >> 16);
  UWBUF(buf_)[6] = (uint8_t) (value >> 8);
  UWBUF(buf_)[7] = (uint8_t) (value);
  buf_->position(buf_->position() + 8);
  return true;
}
bool RWBuffer::write(const void *ptr, size_t len) {
  if (buf_->remaining() < len) return false;
  std::memcpy(buf_->data(), ptr, len);
  buf_->position(buf_->position() + len);
  return true;
}

bool RWBuffer::readUint8(uint8_t *pvalue) {
  if (buf_->remaining() < 1) return false;
  *pvalue = URBUF(buf_)[0];
  buf_->position(buf_->position() + 1);
  return true;
}
bool RWBuffer::readUint16(uint16_t *pvalue) {
  if (buf_->remaining() < 2) return false;
  *pvalue =
      (((uint16_t) URBUF(buf_)[0]) << 8) |
          (((uint16_t) URBUF(buf_)[1]));
  buf_->position(buf_->position() + 2);
  return true;
}
bool RWBuffer::readUint32(uint32_t *pvalue) {
  if (buf_->remaining() < 4) return false;
  *pvalue =
      (((uint32_t) URBUF(buf_)[0]) << 24) |
          (((uint32_t) URBUF(buf_)[1]) << 16) |
          (((uint32_t) URBUF(buf_)[2]) << 8) |
          (((uint32_t) URBUF(buf_)[3]));
  buf_->position(buf_->position() + 4);
  return true;
}
bool RWBuffer::readUint64(uint64_t *pvalue) {
  if (buf_->remaining() < 8) return false;
  *pvalue =
      (((uint64_t) URBUF(buf_)[0]) << 56) |
          (((uint64_t) URBUF(buf_)[1]) << 48) |
          (((uint64_t) URBUF(buf_)[2]) << 40) |
          (((uint64_t) URBUF(buf_)[3]) << 32) |
          (((uint64_t) URBUF(buf_)[4]) << 24) |
          (((uint64_t) URBUF(buf_)[5]) << 16) |
          (((uint64_t) URBUF(buf_)[6]) << 8) |
          (((uint64_t) URBUF(buf_)[7]));
  buf_->position(buf_->position() + 8);
  return true;
}
bool RWBuffer::read(void *ptr, size_t len) {
  if (buf_->remaining() < len) return false;
  std::memcpy(ptr, buf_->data(), len);
  buf_->position(buf_->position() + len);
  return true;
}

} // namespace transport
} // namespace ovpnc
