/**
 * @file	tcp.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-08
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_TRANSPORT_TCP_H_
#define OVPNC_SRC_TRANSPORT_TCP_H_

#include <memory>
#include <vector>

#include <uvw/tcp.h>
#include <uvw/udp.h>

#include <ovpnc/log.h>

#include "transport.h"

namespace ovpnc {

class TransportTCP : public Transport {
 private:
  std::weak_ptr<TransportTCP> self_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<uvw::TCPHandle> handle_;
  bool cleanup_;

  ConnectEventHandler_t connect_handler_;
  CloseEventHandler_t close_handler_;
  ErrorEventHandler_t error_handler_;
  CleanupHandler_t cleanup_handler_;

  std::vector<unsigned char> recv_buffer_;
  int recv_position_;

  TransportTCP(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<Logger> logger);

 public:
  ~TransportTCP() override;

  static std::shared_ptr<TransportTCP> create(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<Logger> logger);

  std::shared_ptr<uvw::Loop> getLoop() override;

  void connect(const sockaddr *addr) override;
  void connect(const uvw::Addr &addr) override;
  void read() override;
  void write(std::unique_ptr<char[]> data, unsigned int len) override;
  void onceConnectEvent(const ConnectEventHandler_t &handler) override;
  void onDataEvent(const DataEventHandler_t &handler) override;
  void onceCloseEvent(const CloseEventHandler_t &handler) override;
  void onceErrorEvent(const ErrorEventHandler_t &handler) override;
  void onceCleanupEvent(const CleanupHandler_t &handler) override;
  void shutdown() override;
  void close() override;
  void cleanup();
};

} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_TCP_H_
