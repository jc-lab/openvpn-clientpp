/**
 * @file	vpn_config.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_VPN_CONFIG_H_
#define OVPNC_VPN_CONFIG_H_

#include <string>
#include <memory>
#include <functional>

namespace ovpnc {

enum TransportProtocol {
  kTransportTcp,
  kTransportUdp
};

enum CertificateFormat {
  kPEM,
  kDER
};

class KeyHandle {
 public:
  virtual ~KeyHandle() = default;
  virtual int sign() = 0;
};

struct VPNConfig {
  TransportProtocol protocol;
  std::string remote_host;
  unsigned int remote_port;
  const sockaddr *sockaddr;

  std::string ca;
  CertificateFormat ca_format;
  std::string cert;
  CertificateFormat cert_format;

  // key_provider
  std::function<std::shared_ptr<KeyHandle>()> key_provider;

  /**
   * "server" or empty
   */
  std::string remote_cert_tls;

  // lzo
  // compress
};

}

#endif //OVPNC_VPN_CONFIG_H_
