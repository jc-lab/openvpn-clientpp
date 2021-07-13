/**
 * @file	tls_provider.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-13
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_TLS_PROVIDER_H_
#define OVPNC_TLS_PROVIDER_H_

#include <memory>

namespace ovpnc {

class TlsProvider {
 public:
  virtual ~TlsProvider() = default;
  virtual std::shared_ptr<TlsLayer>
};

} // namespace ovpnc

#endif //OVPNC_TLS_PROVIDER_H_
