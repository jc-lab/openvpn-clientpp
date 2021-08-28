/**
 * @file	cipher.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-14
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_CRYPTO_CIPHER_H_
#define OVPNC_CRYPTO_CIPHER_H_

#include <memory>
#include <string>
#include <vector>

namespace ovpnc {
namespace crypto {

class CipherContext;

class CipherAlgorithm {
 public:
  virtual ~CipherAlgorithm() = default;
  virtual const std::string& getName() const = 0;

  /**
   * get key size
   * @return bits
   */
  virtual int getKeySize() const = 0;

  /**
   * get block size
   * @return bits
   */
  virtual int getBlockSize() const = 0;

  virtual bool isAEADMode() const = 0;

  virtual std::unique_ptr<CipherContext> createEncipher() = 0;
  virtual std::unique_ptr<CipherContext> createDecipher() = 0;
};

class CipherContext {
 public:
  virtual ~CipherContext() = default;

  /**
   * get key size
   * @return bits
   */
  virtual int getKeyBits() const = 0;

  /**
   * get block size
   * @return bytes
   */
  virtual int getBlockSize() const = 0;

  /**
   * get iv size
   * @return bytes
   */
  virtual int getIVSize() const = 0;

  virtual bool isAEADMode() const = 0;

  /**
   * set tag size
   * @param tag_size bytes
   */
  virtual void setTagSize(int tag_size) = 0;
  /**
   * get tag size
   * @return bytes
   */
  virtual int getTagSize() const = 0;

  virtual void reset(const unsigned char* iv) = 0;

  virtual int init(const unsigned char* key) = 0;

  virtual const std::vector<unsigned char>& iv() const = 0;

  virtual int setAEADTag(const unsigned char* tag) = 0;
  virtual int getAEADTag(unsigned char* tag_buffer) = 0;

  virtual int updateAD(const unsigned char* data, int length) = 0;

  /**
   * process (encrypt or decrypt)
   *
   * @param input_buffer  input data buffer
   * @param input_length  input data length
   * @param output_buffer output data buffer
   * @param output_size   output data buffer size
   * @return              output length
   */
  virtual int updateData(
      const unsigned char* input_buffer,
      int input_length,
      unsigned char* output_buffer,
      int output_size
  ) = 0;

  virtual int final(
      unsigned char* output_buffer,
      int output_size
  ) = 0;
};

} // namespace crypto
} // namespace ovpnc

#endif //OVPNC_CRYPTO_CIPHER_H_
