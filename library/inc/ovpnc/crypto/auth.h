/**
 * @file	auth.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-14
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_CRYPTO_AUTH_H_
#define OVPNC_CRYPTO_AUTH_H_

#include <memory>
#include <string>

namespace ovpnc {
namespace crypto {

class AuthContext;

class AuthAlgorithm {
 public:
  virtual ~AuthAlgorithm() = default;
  virtual const std::string& getName() const = 0;

  virtual bool isNullDigest() const = 0;

  /**
   * get output size
   * @return bits
   */
  virtual int getOutputSize() const = 0;

  virtual std::unique_ptr<AuthContext> create() const = 0;
};

class AuthContext {
 public:
  virtual ~AuthContext() = 0;

  virtual const std::string& getName() const = 0;

  /**
   * get output size
   * @return bits
   */
  virtual int getOutputSize() const = 0;

  virtual int reset() = 0;

  virtual int init(const unsigned char* key) = 0;
};

} // namespace crypto
} // namespace ovpnc

#endif //OVPNC_CRYPTO_AUTH_H_
