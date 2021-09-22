/**
 * @file	multiplexer.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-18
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_TRANSPORT_MULTIPLEXER_H_
#define OVPNC_SRC_TRANSPORT_MULTIPLEXER_H_

#include <stdint.h>

#include <jcu-unio/loop.h>
#include <jcu-unio/log.h>
#include <jcu-unio/buffer.h>
#include <jcu-unio/handle.h>
#include <jcu-unio/shared_object.h>

#include <jcu-unio/net/stream_socket.h>

#include <ovpnc/vpn_config.h>
#include <memory>
#include "reliable_layer.h"

#include "receive_buffer.h"

namespace ovpnc {
namespace transport {

/**
 * Reliability Layer and (de)Multiplexer
 *
 * SSL/TLS -> Reliability Layer -> \
 *            --tls-auth HMAC       \
 *                                   > Multiplexer ----> UDP
 * IP        Encrypt and HMAC       /
 * Tunnel -> using OpenSSL EVP --> /
 * Packets   interface.
 *
 *                                -> Reliability Layer -> SSL/TLS
 *                              /
 * Socket ----> De-multiplexer <
 *                               ↘
 *                                 -> Decrypt -> onRecvDataCallback
 *
 * ================================================================================
 *
 *  * TCP/UDP packet format:
 *
 *   Packet length (16 bits, unsigned) -- TCP only, always sent as
 *       plaintext.  Since TCP is a stream protocol, the packet
 *       length words define the packetization of the stream.
 *
 *   Packet opcode/key_id (8 bits) -- TLS only, not used in
 *       pre-shared secret mode.
 *            packet message type, a P_* constant (high 5 bits)
 *            key_id (low 3 bits, see key_id in struct tls_session
 *              below for comment).  The key_id refers to an
 *              already negotiated TLS session.  OpenVPN seamlessly
 *              renegotiates the TLS session by using a new key_id
 *              for the new session.  Overlap (controlled by
 *              user definable parameters) between old and new TLS
 *              sessions is allowed, providing a seamless transition
 *              during tunnel operation.
 *
 *   Payload (n bytes), which may be a P_CONTROL, P_ACK, or P_DATA
 *       message.
 *
 * ================================================================================
 *
 * RAW Payload -> P_DATA
 *
 * * P_DATA message content: => Multiplexer::data_message_buffer_
 *    - HMAC          : of ciphertext IV + ciphertext (if not disabled by --auth none).
 *    - Ciphertext IV : (size is cipher-dependent, if not disabled by --no-iv).
 *    - Tunnel packet ciphertext.
 *
 * * P_DATA plaintext => Multiplexer::data_plain_buffer_
 *   - packet_id (4 or 8 bytes, if not disabled by --no-replay).
 *       In SSL/TLS mode, 4 bytes are used because the implementation
 *       can force a TLS renegotation before 2^32 packets are sent.
 *       In pre-shared key mode, 8 bytes are used (sequence number
 *       and time_t value) to allow long-term key usage without
 *       packet_id collisions.
 *   - User plaintext (n bytes).
 *
 */
class Multiplexer : public jcu::unio::Socket, public jcu::unio::SharedObject<Multiplexer> {
 public:
  static std::shared_ptr<Multiplexer> create(
      std::shared_ptr<jcu::unio::Loop> loop,
      std::shared_ptr<jcu::unio::Logger> logger,
      const VPNConfig &vpn_config,
      std::shared_ptr<jcu::unio::Resource> io_parent,
      std::shared_ptr<ReliableLayer> reliable
  );

 private:
  std::weak_ptr<Multiplexer> self_;
  std::weak_ptr<jcu::unio::Resource> io_parent_;

  std::shared_ptr<jcu::unio::Loop> loop_;
  std::shared_ptr<jcu::unio::Logger> logger_;

  VPNConfig vpn_config_;
  std::shared_ptr<ReliableLayer> reliable_;

  uint32_t local_data_packet_id_;
  uint32_t peer_data_packet_id_;

  int mtu_;

  std::shared_ptr<jcu::unio::StreamSocket> parent_socket_;

  /**
   * TCP/UDP packet format [as offset=3] + P_DATA message content
   */
  std::shared_ptr<jcu::unio::Buffer> send_message_buffer_;

  /**
   * TCP/UDP packet format [as offset=3] + P_DATA message content
   */
  std::shared_ptr<ReceiveBuffer> recv_message_buffer_;

  /**
   * Plain IP Protocol Buffer
   */
  std::shared_ptr<jcu::unio::Buffer> read_buffer_;
  jcu::unio::CompletionManyCallback<jcu::unio::SocketReadEvent> read_callback_;

  Multiplexer(
      std::shared_ptr<jcu::unio::Loop> loop,
      std::shared_ptr<jcu::unio::Logger> logger,
      const VPNConfig &vpn_config,
      std::shared_ptr<jcu::unio::Resource> io_parent,
      std::shared_ptr<ReliableLayer> reliable
  );

  void onRead(ReceiveBuffer *buffer);
  void handleReceivedPacket(ReliableLayer::LazyAckContext &ack_context, uint16_t packet_id, ReceiveBuffer *buffer);

 public:
  std::shared_ptr<Multiplexer> shared() const override;

  /**
   * create buffers
   *
   * @param mtu required to allocate buffers
   */
  void init(int mtu);

  void connect(jcu::unio::CompletionOnceCallback<jcu::unio::SocketConnectEvent> callback);

  bool isTLS() const;
  bool isTCP() const;

  /**
   * required socket header size
   *
   * @return maybe 3
   */
  int getRequiredSocketHeader() const;

  /**
   * required data plain buffer (for header)
   *
   *  * P_CONTROL message format:
   *
   *   local session_id (random 64 bit value to identify TLS session).
   *   HMAC signature of entire encapsulation header for integrity
   *       check if --tls-auth is specified (usually 16 or 20 bytes).
   *   packet-id for replay protection (4 or 8 bytes, includes
   *       sequence number and optional time_t timestamp).
   *   P_ACK packet_id array length (1 byte).
   *   P_ACK packet-id array (if length > 0).
   *   P_ACK remote session_id (if length > 0).
   *   message packet-id (4 bytes).
   *   TLS payload ciphertext (n bytes) (only for P_CONTROL).
   *
   * @return maybe 3(TCP Header) + 20(HMAC Signature) + 8(packet-id) + 1(P_ACK packet_id array length) +
   *         4 * 255 (P_ACK packet_id array) + 8(P_ACK remote session_id) + 4(message packet_id) = 1064
   */
  int getRequiredMessageBufferOffset() const;

  /**
   * required data plain buffer (for header)
   *
   * @return maybe 8
   */
  int getRequiredDataPlainBufferOffset() const;

  /**
   * create payload buffer
   *
   * requiredMessageBufferOffset + mtu
   *
   * @return created buffer
   */
  std::shared_ptr<jcu::unio::Buffer> createMessageBuffer();

  /**
   * create data plain buffer
   *
   * 8 byte packet_id [as offset=8] + plain text
   *
   * @return created data plain buffer
   */
  std::shared_ptr<jcu::unio::Buffer> createDataPlainBuffer();

  /**
   * send data
   *
   * application:
   *   1. data_buffer = createDataPlainBuffer()
   *   2. write data into data_buffer at any time.
   *   3. multiplexer->send(data_buffer)
   *   3.1. encrypt data_buffer into data_message_buffer_.
   *   3.2. write data_message_buffer_ to the socket.
   *
   * @param buffer plain text payload
   */
  void sendData(std::shared_ptr<jcu::unio::Buffer> buffer);

  /**
   * register P_DATA receive callback
   *
   * @param callback plain_buffer is data_plain_recv_buffer_
   */
  void onRecvDataCallback(std::function<void(std::shared_ptr<jcu::unio::Buffer> plain_buffer)> callback);

  /**
   * write to transport socket
   *
   * @param op_code
   * @param buffer
   * @param callback
   */
  void write(
      uint8_t op_code,
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
  );

  bool isConnected() const;
  bool isHandshaked() const;

  void read(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionManyCallback<jcu::unio::SocketReadEvent> callback
  ) override;
  void cancelRead() override;
  void write(
      std::shared_ptr<jcu::unio::Buffer> buffer,
      jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
  ) override;
  void close() override;
};

} // namespace transport
} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_MULTIPLEXER_H_
