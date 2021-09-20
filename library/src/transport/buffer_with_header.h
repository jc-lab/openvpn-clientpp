/**
 * @file	buffer_with_header.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-20
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_BUFFER_WITH_HEADER_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_BUFFER_WITH_HEADER_H_

#include <stddef.h>
#include <vector>
#include <jcu-unio/buffer.h>

namespace ovpnc {
namespace transport {

class BufferWithHeader : public jcu::unio::Buffer {
 protected:
  std::vector<char> buf_;
  size_t header_size_;
  size_t position_;
  size_t limit_;

 public:
  BufferWithHeader(size_t header_size, size_t size);
  void *base() override;
  const void *base() const override;
  void *data() override;
  const void *data() const override;
  size_t capacity() const override;
  size_t position() const override;
  void position(size_t size) override;
  void limit(size_t size) override;
  size_t remaining() const override;
  void flip() override;
  void clear() override;
  size_t getExpandableSize() const override;
  void expand(size_t size) override;
};

} // namespace transport
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_BUFFER_WITH_HEADER_H_
