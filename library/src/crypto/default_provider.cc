/**
 * @file	default_provider.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-15
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "default_provider.h"

#include "openssl_aes_gcm.h"
#include "null_digest.h"

namespace ovpnc {
namespace crypto {

DefaultProvider::DefaultProvider() {
  ciphers_.emplace("AES-128-GCM", std::make_shared<AesGcmAlgorithm>(128));
  ciphers_.emplace("AES-192-GCM", std::make_shared<AesGcmAlgorithm>(192));
  ciphers_.emplace("AES-256-GCM", std::make_shared<AesGcmAlgorithm>(256));

  auths_.emplace("none", std::make_shared<NullDigestAlgorithm>());
  auths_.emplace("[null-digest]", std::make_shared<NullDigestAlgorithm>());
}

std::shared_ptr<CipherAlgorithm> DefaultProvider::getCipherAlgorithm(const std::string &name) const {
  const auto it = ciphers_.find(name);
  if (it == ciphers_.cend()) {
    return nullptr;
  }
  return it->second;
}

std::shared_ptr<AuthAlgorithm> DefaultProvider::getAuthAlgorithm(const std::string &name) const {
  const auto it = auths_.find(name);
  if (it == auths_.cend()) {
    return nullptr;
  }
  return it->second;
}

std::list<std::string> DefaultProvider::getCipherAlgorithmList() const {
  std::list<std::string> list;
  for (auto it = ciphers_.cbegin(); it != ciphers_.cend(); it++) {
    list.emplace_back(it->first);
  }
  return std::move(list);
}

std::list<std::string> DefaultProvider::getAuthAlgorithmList() const {
  std::list<std::string> list;
  for (auto it = auths_.cbegin(); it != auths_.cend(); it++) {
    list.emplace_back(it->first);
  }
  return std::move(list);
}

} // namespace crypto
} // namespace ovpnc
