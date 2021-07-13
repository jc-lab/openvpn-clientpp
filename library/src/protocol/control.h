/**
 * @file	control.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-11
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_PROTOCOL_CONTROL_H_
#define OVPNC_SRC_PROTOCOL_CONTROL_H_

#include <stdint.h>

#include <string>

#include "base.h"

namespace ovpnc {
namespace protocol {
namespace control {

struct KeySource {
  uint8_t pre_master[48];     /**< Random used for master secret
                                 *   generation, provided only by client
                                 *   OpenVPN peer. */
  uint8_t random1[32];        /**< Seed used for master secret
                                 *   generation, provided by both client
                                 *   and server. */
  uint8_t random2[32];        /**< Seed used for key expansion, provided
                                 *   by both client and server. */
};

/**
 * Key Method 2
 *
 * Description:
 *   Literal 0 (4 bytes).
 *   key_method type (1 byte).
 *   \ref KeySource "KeySource structure" (pre_master only defined for client ->
 *       server).
 *   options_string_length, including null (2 bytes).
 *   Options string (n bytes, null terminated, client/server options
 *       string must match).
 *   [The username/password data below is optional, record can end
 *       at this point.]
 *   username_string_length, including null (2 bytes).
 *   Username string (n bytes, null terminated).
 *   password_string_length, including null (2 bytes).
 *   Password string (n bytes, null terminated).
 */
class KeyMethod2 : public PayloadBase {
 private:
  bool is_server_;
  KeySource key_source_;
  std::string option_string_;
  std::string username_;
  std::string password_;

 public:
  KeyMethod2();
  void init(bool is_server, const KeySource *key_source = nullptr);
  const KeySource &keySource() const {
    return key_source_;
  }
  void setOptionString(const std::string &option_string) {
    option_string_ = option_string;
  }
  const std::string &optionsString() const {
    return option_string_;
  }
  void setUsername(const std::string &username) {
    username_ = username;
  }
  void setPassword(const std::string &password) {
    password_ = password;
  }
  int getSerializedSize() const override;
  unsigned char *serializeTo(unsigned char *buffer) const override;
  int deserializeFrom(const unsigned char *buffer, int length) override;
};

} // namespace control
} // namespace protocol
} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_CONTROL_H_
