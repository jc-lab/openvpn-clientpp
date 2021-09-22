/**
 * @file	rw_buffer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-22
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_RW_BUFFER_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_RW_BUFFER_H_

#include <stdint.h>

#include <jcu-unio/buffer.h>

namespace ovpnc {
namespace transport {

class RWBuffer {
 private:
  jcu::unio::Buffer* buf_;

 public:
  explicit RWBuffer(jcu::unio::Buffer* buf);
  void flip();

  unsigned char* data();
  size_t remaining() const;
  bool skip(int length);

  bool writeUint8(uint8_t value);
  bool writeUint16(uint16_t value);
  bool writeUint32(uint32_t value);
  bool writeUint64(uint64_t value);
  bool write(const void* ptr, size_t len);

  bool readUint8(uint8_t* pvalue);
  bool readUint16(uint16_t* pvalue);
  bool readUint32(uint32_t* pvalue);
  bool readUint64(uint64_t* pvalue);
  bool read(void* ptr, size_t len);
};

} // namespace transport
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_RW_BUFFER_H_
