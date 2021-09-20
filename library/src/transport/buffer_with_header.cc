/**
 * @file	buffer_with_header.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-20
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "buffer_with_header.h"

namespace ovpnc {
namespace transport {

BufferWithHeader::BufferWithHeader(size_t header_size, size_t size) :
  header_size_(header_size), position_(header_size), limit_(0), buf_(size)
{
}

void *BufferWithHeader::base() {
  return buf_.data();
}
const void *BufferWithHeader::base() const {
  return buf_.data();
}
void *BufferWithHeader::data() {
  return buf_.data() + position();
}
const void *BufferWithHeader::data() const {
  return buf_.data() + position();
}
size_t BufferWithHeader::capacity() const {
  return buf_.size();
}
size_t BufferWithHeader::position() const {
  return position_;
}
void BufferWithHeader::position(size_t size) {
  position_ = size;
}
void BufferWithHeader::limit(size_t size) {
  limit_ = size;
}
size_t BufferWithHeader::remaining() const {
  return limit_ - position_;
}
void BufferWithHeader::flip() {
  limit_ = position_;
  position_ = header_size_;
}
void BufferWithHeader::clear() {
  position_ = header_size_;
  limit_ = capacity() - header_size_;
}
size_t BufferWithHeader::getExpandableSize() const {
  return buf_.size();
}
void BufferWithHeader::expand(size_t size) {
}

} // namespace transport
} // namespace ovpnc
