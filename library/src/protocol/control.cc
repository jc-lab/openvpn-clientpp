/**
 * @file	control.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-11
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <sstream>

#include "control.h"

#include <openssl/rand.h>

#ifdef _MSC_VER
#define STRTOK_R_FUNCTION strtok_s
#else
#define STRTOK_R_FUNCTION strtok_r
#endif

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
  const unsigned char *p = buffer;

  // Literal 0
  if (*(p++) != 0) return -2;
  if (*(p++) != 0) return -2;
  if (*(p++) != 0) return -2;
  if (*(p++) != 0) return -2;

  // key method + flag
  if (*(p++) != 2) return -2;

  if (!is_server_) {
    std::memcpy(key_source_.pre_master, p, sizeof(key_source_.pre_master));
    p += sizeof(key_source_.pre_master);
  }

  std::memcpy(key_source_.random1, p, sizeof(key_source_.random1));
  p += sizeof(key_source_.random1);

  std::memcpy(key_source_.random2, p, sizeof(key_source_.random2));
  p += sizeof(key_source_.random2);

  uint16_t option_string_length = 0;
  option_string_length |= ((uint16_t)*(p++)) << 8;
  option_string_length |= ((uint16_t)*(p++));
  option_string_.clear();
  option_string_.insert(option_string_.end(), p, p + option_string_length);
  option_string_.erase(std::find(option_string_.begin(), option_string_.end(), '\0'), option_string_.end());
  p += option_string_length;

  if (!username_.empty() && !password_.empty()) {
    uint16_t username_length = 0;
    username_length |= ((uint16_t)*(p++)) << 8;
    username_length |= ((uint16_t)*(p++));
    username_.clear();
    username_.insert(username_.end(), p, p + username_length);
    username_.erase(std::find(username_.begin(), username_.end(), '\0'), username_.end());
    p += username_length;

    uint16_t password_length = 0;
    password_length |= ((uint16_t)*(p++)) << 8;
    password_length |= ((uint16_t)*(p++));
    password_.clear();
    password_.insert(password_.end(), p, p + password_length);
    password_.erase(std::find(password_.begin(), password_.end(), '\0'), password_.end());
    p += password_length;
  }

  return p - buffer;
}

std::string DataChannelOptions::serialize() const {
  std::stringstream ss;
  ss << "V4";
  ss << ",dev-type " << dev_type;
  ss << ",link-mtu " << link_mtu;
  ss << ",tun-mtu ";
  ss << ",proto " << proto;
  // keydir 0 : server
  // keydir 1 : client
  ss << ",cipher " << cipher;
  ss << ",auth " << auth;
  ss << ",keysize " << key_size;
//  option_string << ",tls-auth";
  ss << ",key-method " << key_method;
  if (tls_direction == kTlsDirectionServer) {
    ss << ",tls-server";
  } else if (tls_direction == kTlsDirectionClient) {
    ss << ",tls-client";
  }
  return ss.str();
}

bool DataChannelOptions::deserialize(const std::string &input) {
  static const std::string C_DEV_TYPE("dev-type ");
  static const std::string C_LINK_MTU("link-mtu ");
  static const std::string C_TUN_MTU("tun-mtu ");
  static const std::string C_PROTO("proto ");
  static const std::string C_CIPHER("cipher ");
  static const std::string C_AUTH("auth ");
  static const std::string C_KEYSIZE("keysize ");
  static const std::string C_KEY_METHOD("key-method ");
  static const std::string C_TLS_SERVER("tls-server");
  static const std::string C_TLS_CLIENT("tls-client");

  std::string buffer(input);
  const char* token;
  char* context = nullptr;
  int index = 0;

  version.clear();
  dev_type.clear();
  link_mtu = 0;
  tun_mtu = 0;
  proto.clear();
  cipher.clear();
  auth.clear();
  key_size = 0;
  key_method = 0;
  tls_direction = kTlsDirectionNone;

  token = STRTOK_R_FUNCTION(buffer.data(), ",", &context);
  while (token) {
    if (index == 0) {
      version = token;
    } else {
      if (strstr(token, C_DEV_TYPE.c_str()) == token) {
        dev_type = token + C_DEV_TYPE.length();
      } else if (strstr(token, C_LINK_MTU.c_str()) == token) {
        const char* cval = token + C_LINK_MTU.length();
        link_mtu = strtol(cval, nullptr, 10);
      } else if (strstr(token, C_TUN_MTU.c_str()) == token) {
        const char* cval = token + C_TUN_MTU.length();
        tun_mtu = strtol(cval, nullptr, 10);
      } else if (strstr(token, C_PROTO.c_str()) == token) {
        proto = token + C_PROTO.length();
      } else if (strstr(token, C_CIPHER.c_str()) == token) {
        cipher = token + C_CIPHER.length();
      } else if (strstr(token, C_AUTH.c_str()) == token) {
        auth = token + C_AUTH.length();
      } else if (strstr(token, C_KEYSIZE.c_str()) == token) {
        const char* cval = token + C_KEYSIZE.length();
        key_size = strtol(cval, nullptr, 10);
      } else if (strstr(token, C_KEY_METHOD.c_str()) == token) {
        const char* cval = token + C_KEY_METHOD.length();
        key_method = strtol(cval, nullptr, 10);
      } else if (strstr(token, C_TLS_SERVER.c_str()) == token) {
        tls_direction = kTlsDirectionServer;
      } else if (strstr(token, C_TLS_CLIENT.c_str()) == token) {
        tls_direction = kTlsDirectionClient;
      }
    }
    index++;
    token = STRTOK_R_FUNCTION(nullptr, ",", &context);
  }
  return true;
}

} // namespace control
} // namespace protocol
} // namespace ovpnc

