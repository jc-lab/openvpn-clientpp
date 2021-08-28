/**
 * @file	openssl_aes_gcm.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-14
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPENSSL_AES_GCM_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPENSSL_AES_GCM_H_

#include <ovpnc/crypto/provider.h>
#include <ovpnc/crypto/cipher.h>

namespace ovpnc {
namespace crypto {

class AesGcmAlgorithm : public CipherAlgorithm {
 private:
  int key_size_;
  std::string name_;

 public:
  AesGcmAlgorithm(int key_size);
  ~AesGcmAlgorithm() override;
  const std::string &getName() const override;
  int getKeySize() const override;
  int getBlockSize() const override;
  bool isAEADMode() const override;
  std::unique_ptr<CipherContext> createEncipher() override;
  std::unique_ptr<CipherContext> createDecipher() override;
};

} // namespace crypto
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPENSSL_AES_GCM_H_
