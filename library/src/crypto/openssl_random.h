/**
 * @file	openssl_random.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-20
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPEN_SSL_RANDOM_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPEN_SSL_RANDOM_H_

#include <ovpnc/crypto/provider.h>

namespace ovpnc {
namespace crypto {

class OpenSSLRandom : public Random {
 public:
  int nextBytes(void* buf, size_t size) override;
};

} // namespace crypto
} // namespace ovpnc

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_CRYPTO_OPEN_SSL_RANDOM_H_
