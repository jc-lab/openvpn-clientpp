/**
 * @file	null_digest.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-16
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "null_digest.h"

namespace ovpnc {
namespace crypto {

const std::string &NullDigestAlgorithm::getName() const {
  return "[null-digest]";
}

bool NullDigestAlgorithm::isNullDigest() const {
  return true;
}

int NullDigestAlgorithm::getOutputSize() const {
  return 0;
}

std::unique_ptr<AuthContext> NullDigestAlgorithm::create() const {
  return std::unique_ptr<AuthContext>();
}

} // namespace crypto
} // namespace ovpnc
