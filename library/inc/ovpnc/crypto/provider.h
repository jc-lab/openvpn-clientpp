/**
 * @file	provider.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-15
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_CRYPTO_PROVIDER_H_
#define OVPNC_CRYPTO_PROVIDER_H_

#include <memory>
#include <string>
#include <list>

namespace ovpnc {
namespace crypto {

class CipherAlgorithm;
class AuthAlgorithm;

class Provider {
 public:
  virtual ~Provider() = default;

  virtual std::shared_ptr<CipherAlgorithm> getCipherAlgorithm(const std::string& name) const = 0;
  virtual std::shared_ptr<AuthAlgorithm> getAuthAlgorithm(const std::string& name) const = 0;

  virtual std::list<std::string> getCipherAlgorithmList() const = 0;
  virtual std::list<std::string> getAuthAlgorithmList() const = 0;
};

} // namespace crypto
} // namespace ovpnc

#endif //OVPNC_CRYPTO_PROVIDER_H_
