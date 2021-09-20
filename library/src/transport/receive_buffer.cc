/**
 * @file	receive_buffer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-20
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "receive_buffer.h"

namespace ovpnc {
namespace transport {

ReceiveBuffer::ReceiveBuffer(size_t size) :
    position_(0), limit_(0), buf_(size), read_more_(false)
{
}

void *ReceiveBuffer::base() {
  return buf_.data();
}
const void *ReceiveBuffer::base() const {
  return buf_.data();
}
void *ReceiveBuffer::data() {
  return buf_.data() + position();
}
const void *ReceiveBuffer::data() const {
  return buf_.data() + position();
}
size_t ReceiveBuffer::capacity() const {
  return buf_.size();
}
size_t ReceiveBuffer::position() const {
  return position_;
}
void ReceiveBuffer::position(size_t size) {
  position_ = size;
}
void ReceiveBuffer::limit(size_t size) {
  limit_ = size;
}
size_t ReceiveBuffer::remaining() const {
  return limit_ - position_;
}
void ReceiveBuffer::flip() {
  limit_ = position_;
  position_ = 0;
}
void ReceiveBuffer::clear() {
  if (read_more_) return ;
  position_ = 0;
  limit_ = capacity();
}
size_t ReceiveBuffer::getExpandableSize() const {
  return buf_.size();
}
void ReceiveBuffer::expand(size_t size) {
}

void ReceiveBuffer::setReadMore() {
  size_t new_size = remaining();
  std::memmove(base(), data(), new_size);
  read_more_ = true;
  position_ = new_size;
  limit_ = capacity();
}

void ReceiveBuffer::clearReadMore() {
  read_more_ = false;
}

} // namespace transport
} // namespace ovpnc
