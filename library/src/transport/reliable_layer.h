/**
 * @file	reliable_layer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-10
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_
#define OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "../log.h"
#include "transport.h"

#include "../protocol/reliable.h"
#include "openssl_tls.h"

namespace ovpnc {

class ReliableLayer : public Transport {
 private:
  enum State {
    kUnknownState = 0,
    kReliableHandshakingState,
    kTlsHandshakingState,
    kEstablishedState,
    kHandshakeFailedState
  };

  std::weak_ptr<ReliableLayer> self_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<Transport> transport_;
  bool cleanup_;

  ConnectEventHandler_t connect_handler_;
  CloseEventHandler_t close_handler_;
  ErrorEventHandler_t error_handler_;
  CleanupHandler_t cleanup_handler_;
  DataEventHandler_t data_handler_;

  State state_;
  std::shared_ptr<TlsLayer> tls_layer_;

  uint32_t local_packet_id_;
  uint32_t peer_packet_id_;
  unsigned char session_id_[8];
  unsigned char peer_session_id_[8];
  std::vector<unsigned char> recv_buffer_;
  int recv_position_;

  ReliableLayer(std::shared_ptr<Transport> transport, std::shared_ptr<Logger> event);

  void sessionInit();
  void handshake();

  void processInbound(Transport::DataEvent &event);
  void processPacketInbound(const unsigned char *buffer, int length);
  void processControlHardResetServerV2(protocol::reliable::OpCode op_code,
                                       const unsigned char *raw_payload,
                                       int length); // P_CONTROL_HARD_RESET_SERVER_V2
  void processControlV1(protocol::reliable::OpCode op_code,
                        const unsigned char *raw_payload,
                        int length); // P_CONTROL_V1

  void sendSimplePayload(const protocol::reliable::ReliablePayload *payload);

  void sendAckV1(int packet_id_count, uint32_t *packet_ids);

  void cleanup();

 private:
  void tlsInit();
  void postHandshaked();

 public:
  ~ReliableLayer();

  static std::shared_ptr<ReliableLayer> create(std::shared_ptr<Transport> transport, std::shared_ptr<Logger> logger);

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

  void initControlV1PayloadToSend(protocol::reliable::ControlV1Payload *payload);
  void initAckV1PayloadToSend(protocol::reliable::AckV1Payload *payload);
  void writeRawPacket(std::unique_ptr<char[]> data, unsigned int len);
};

} // namespace ovpnc

#endif //OVPNC_SRC_PROTOCOL_RELIABLE_LAYER_H_
