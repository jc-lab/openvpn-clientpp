/**
 * @file	base.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-11
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OVPNC_SRC_PROTOCOL_BASE_H_
#define OVPNC_SRC_PROTOCOL_BASE_H_

namespace ovpnc {
namespace protocol {

class PayloadBase {
 public:
  virtual ~PayloadBase() = default;
  virtual int getSerializedSize() const = 0;
  virtual unsigned char *serializeTo(unsigned char *buffer) const = 0;
  virtual int deserializeFrom(const unsigned char *buffer, int length) = 0;
};

} // namespace protocol
} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_BASE_H_
