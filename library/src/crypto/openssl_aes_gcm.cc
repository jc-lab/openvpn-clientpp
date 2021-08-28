/**
 * @file	openssl_aes_gcm.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-14
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <memory>
#include <sstream>
#include <vector>

#include "openssl_aes_gcm.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace ovpnc {
namespace crypto {

struct EVP_CIPHER_CTX_Deleter {
  void operator()(void* ptr) {
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ptr);
  }
};

class AesGcmCipherContext : public CipherContext {
 private:
  int key_size_;
  bool decrypt_mode_;
  const EVP_CIPHER* evp_cipher_;
  std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> evp_cipher_ctx_;
  std::vector<unsigned char> iv_;
  int tag_size_;

 public:
  AesGcmCipherContext(int key_size, bool decrypt_mode) :
    key_size_(key_size),
    decrypt_mode_(decrypt_mode),
    evp_cipher_(nullptr),
    tag_size_(0)
  {
    evp_cipher_ctx_.reset(EVP_CIPHER_CTX_new());
  }

  ~AesGcmCipherContext() override {}

  void reset(const unsigned char* iv) override {
    EVP_CipherInit_ex(evp_cipher_ctx_.get(), NULL, NULL, NULL, iv, -1);
  }

  int init(const unsigned char* key) override {
    switch(key_size_)
    {
      case 128: evp_cipher_ = EVP_aes_128_gcm(); break;
      case 192: evp_cipher_ = EVP_aes_192_gcm(); break;
      case 256: evp_cipher_ = EVP_aes_256_gcm(); break;
      default: break;
    }

    auto ctx = evp_cipher_ctx_.get();
    int evp_enc = decrypt_mode_ ? 0 : 1;
    EVP_CIPHER_CTX_reset(ctx);
    if (!EVP_CipherInit(ctx, evp_cipher_, nullptr, nullptr, evp_enc))
    {
      return -1;
    }
    if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key, nullptr, evp_enc))
    {
      return -1;
    }
    return 0;
  }

  const std::vector<unsigned char> &iv() const override {
    return iv_;
  }

  int setAEADTag(const unsigned char* tag) override {
    EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)evp_cipher_ctx_.get(), EVP_CTRL_AEAD_SET_TAG, tag_size_, (void*)tag);
    return 0;
  }

  int getAEADTag(unsigned char* tag_buffer) override {
    EVP_CIPHER_CTX_ctrl(evp_cipher_ctx_.get(), EVP_CTRL_AEAD_GET_TAG, tag_size_, tag_buffer);
    return 0;
  }

  int getKeyBits() const override {
    return key_size_;
  }

  int getBlockSize() const override {
    return 16;
  }
  int getIVSize() const override {
    return EVP_CIPHER_CTX_iv_length(evp_cipher_ctx_.get());
  }
  bool isAEADMode() const override {
    return true;
  }

  void setTagSize(int tag_size) override {
    tag_size_ = tag_size;
  }

  int getTagSize() const override {
    return tag_size_;
  }

  int updateAD(const unsigned char *data, int length) override {
    int outl = 0;
    if (!EVP_CipherUpdate(evp_cipher_ctx_.get(), nullptr, &outl, data, length)) {
      return -1;
    }
    return 0;
  }

  int updateData(
      const unsigned char *input_buffer,
      int input_length,
      unsigned char *output_buffer,
      int output_size
  ) override {
    int outl = output_size;
    if (!EVP_CipherUpdate(evp_cipher_ctx_.get(), output_buffer, &outl, input_buffer, input_length)) {
      return -1;
    }
    return outl;
  }

  int final(unsigned char *output_buffer, int output_size) override {
    int outl = output_size;
    if (!EVP_CipherFinal(evp_cipher_ctx_.get(), output_buffer, &outl)) {
      return -1;
    }
    return outl;
  }
};

AesGcmAlgorithm::AesGcmAlgorithm(int key_size) :
    key_size_(key_size)
{
  std::stringstream ss;
  ss << "AES-" << key_size_ << "-GCM";
  name_ = ss.str();
}

AesGcmAlgorithm::~AesGcmAlgorithm() {
}

const std::string &AesGcmAlgorithm::getName() const {
  return name_;
}

int AesGcmAlgorithm::getKeySize() const {
  return key_size_;
}

int AesGcmAlgorithm::getBlockSize() const {
  return 128;
}

bool AesGcmAlgorithm::isAEADMode() const {
  return true;
}

std::unique_ptr<CipherContext> AesGcmAlgorithm::createEncipher() {
  return std::make_unique<AesGcmCipherContext>(key_size_, false);
}

std::unique_ptr<CipherContext> AesGcmAlgorithm::createDecipher() {
  return std::make_unique<AesGcmCipherContext>(key_size_, true);
}

} // namespace crypto
} // namespace ovpnc
