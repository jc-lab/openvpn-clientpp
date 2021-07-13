/**
 * @file	control.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-11
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "control.h"

#include <openssl/rand.h>

namespace ovpnc {
namespace protocol {
namespace control {

KeyMethod2::KeyMethod2() :
    is_server_(false) {
}

void KeyMethod2::init(bool is_server, const KeySource *key_source) {
  is_server_ = is_server;
  option_string_.clear();
  username_.clear();
  password_.clear();
  if (key_source) {
    key_source_ = *key_source;
  } else {
    RAND_bytes(key_source_.pre_master, sizeof(key_source_.pre_master));
    RAND_bytes(key_source_.random1, sizeof(key_source_.random1));
    RAND_bytes(key_source_.random2, sizeof(key_source_.random2));
  }
}

int KeyMethod2::getSerializedSize() const {
  int size = 71; // 4 + 1 + 64 + 2
  if (!is_server_) {
    size += 48;
  }
  size += option_string_.length() + 1;
  if (!username_.empty() && !password_.empty()) {
    size += 2 + username_.length() + 1;
    size += 2 + password_.length() + 1;
  }
  return size;
}

unsigned char *KeyMethod2::serializeTo(unsigned char *buffer) const {
  unsigned char *p = buffer;

  // Literal 0
  *(p++) = 0;
  *(p++) = 0;
  *(p++) = 0;
  *(p++) = 0;

  // key method + flag
  *(p++) = 2;

  if (!is_server_) {
    std::memcpy(p, key_source_.pre_master, sizeof(key_source_.pre_master));
    p += sizeof(key_source_.pre_master);
  }

  std::memcpy(p, key_source_.random1, sizeof(key_source_.random1));
  p += sizeof(key_source_.random1);

  std::memcpy(p, key_source_.random2, sizeof(key_source_.random2));
  p += sizeof(key_source_.random2);

  uint16_t option_string_length = option_string_.length() + 1;
  *(p++) = (uint8_t) (option_string_length >> 8);
  *(p++) = (uint8_t) (option_string_length);
  std::memcpy(p, option_string_.c_str(), option_string_length);
  p += option_string_length;

  if (!username_.empty() && !password_.empty()) {
    uint16_t username_length = username_.length() + 1;
    *(p++) = (uint8_t) (username_length >> 8);
    *(p++) = (uint8_t) (username_length);
    std::memcpy(p, username_.c_str(), username_length);
    p += username_length;

    uint16_t password_length = password_.length() + 1;
    *(p++) = (uint8_t) (password_length >> 8);
    *(p++) = (uint8_t) (password_length);
    std::memcpy(p, password_.c_str(), password_length);
    p += password_length;
  }

  return p;
}

int KeyMethod2::deserializeFrom(const unsigned char *buffer, int length) {
  return -1;
}

} // namespace control
} // namespace protocol
} // namespace ovpnc

