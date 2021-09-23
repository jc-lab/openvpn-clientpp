/**
 * @file	push_options.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-23
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_INC_OVPNC_PUSH_OPTIONS_H_
#define OPENVPN_CLIENTPP_LIBRARY_INC_OVPNC_PUSH_OPTIONS_H_

#include <string>
#include <map>
#include <list>

namespace ovpnc {

class PushOptions {
 public:
  typedef std::map<std::string, std::list<std::string>> MapType;

 protected:
  MapType raw_;

 public:
  const MapType& map() const {
    return raw_;
  }

  MapType& map() {
    return raw_;
  }

  std::string findFirst(const char* key) const {
    const auto it = raw_.find(key);
    if (it != raw_.cend()) {
      if (!it->second.empty()) return it->second.front();
    }
    return std::string();
  }

  std::list<std::string> find(const char* key) const {
    const auto it = raw_.find(key);
    if (it != raw_.cend()) {
      return it->second;
    }
    return std::list<std::string>();
  }

  void set(const char* key, const std::list<std::string>& list) {
    raw_[key] = list;
  }

  void add(const char* key, const std::string& value) {
    raw_[key].emplace_back(value);
  }

  void parseFrom(const std::string& buffer);
};

} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_INC_OVPNC_PUSH_OPTIONS_H_
