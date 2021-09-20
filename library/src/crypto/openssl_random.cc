/**
 * @file	openssl_random.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-20
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <openssl/rand.h>
#include <openssl/err.h>

#include "openssl_random.h"

namespace ovpnc {
namespace crypto {

int OpenSSLRandom::nextBytes(void *buf, size_t size) {
  if (RAND_bytes((unsigned char*)buf, size) == 1) {
    return 0;
  }
  return (int) ERR_get_error();
}

} // namespace crypto
} // namespace ovpnc
