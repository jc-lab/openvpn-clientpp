/**
 * @file	push_options.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-23
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <assert.h>
#include <ovpnc/push_options.h>

#ifndef _MSC_VER
#define strtok_s strtok_r
#endif

namespace ovpnc {

void PushOptions::parseFrom(const std::string &input) {
  std::string buffer(input);
  char* token;
  char* context = nullptr;

  raw_.clear();

  token = strtok_s(buffer.data(), ",", &context);
  while (token) {
    char* value = nullptr;
    const char* key = strtok_s(token, " ", &value);
    assert(key);

    auto& list = raw_[key];
    list.emplace_back(value);

    token = strtok_s(nullptr, ",", &context);
  }

  // PUSH_REPLY,route 192.168.20.0 255.255.255.0,redirect-gateway def1 bypass-dhcp,dhcp-option DNS 8.8.8.8,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.4 255.255.255.0
  // route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.4 255.255.255.0
}

} // namespace ovpnc
