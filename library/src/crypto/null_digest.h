/**
 * @file	null_digest.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-16
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_NULL_DIGEST_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_NULL_DIGEST_H_

#include <ovpnc/crypto/auth.h>

namespace ovpnc {
namespace crypto {

class NullDigestAlgorithm : public AuthAlgorithm {
 public:
  const std::string &getName() const override;
  bool isNullDigest() const override;
  int getOutputSize() const override;
  std::unique_ptr<AuthContext> create() const override;
};

} // namespace crypto
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_NULL_DIGEST_H_
