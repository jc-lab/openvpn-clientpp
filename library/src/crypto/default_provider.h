/**
 * @file	default_provider.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-15
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_DEFAULT_PROVIDER_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_DEFAULT_PROVIDER_H_

#include <memory>
#include <string>
#include <map>

#include <ovpnc/crypto/provider.h>

namespace ovpnc {
namespace crypto {

class DefaultProvider : public Provider {
 private:
  std::map<std::string, std::shared_ptr<CipherAlgorithm>> ciphers_;
  std::map<std::string, std::shared_ptr<AuthAlgorithm>> auths_;
 public:
  DefaultProvider();

  std::shared_ptr<Random> createRandom() const override;
  std::shared_ptr<CipherAlgorithm> getCipherAlgorithm(const std::string &name) const override;
  std::shared_ptr<AuthAlgorithm> getAuthAlgorithm(const std::string &name) const override;
  std::list<std::string> getCipherAlgorithmList() const override;
  std::list<std::string> getAuthAlgorithmList() const override;
};

} // namespace crypto
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_DEFAULT_PROVIDER_H_
