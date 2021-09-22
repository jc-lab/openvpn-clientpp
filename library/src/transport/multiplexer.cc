/**
 * @file	multiplexer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-09-18
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <assert.h>

#include <jcu-unio/net/tcp_socket.h>

#include "multiplexer.h"

#include "buffer_with_header.h"

namespace ovpnc {
namespace transport {

static int alignedSize(int size, int align) {
  int x = size % align;
  if (x) {
    size += align - x;
  }
  return size;
}

static void dump(void* ptr, int size) {
  const unsigned char* p = (const unsigned char*)ptr;
  fprintf(stderr, "DUMP (%d) \n", size);
  for (int i=0; i<size; i++) fprintf(stderr, "%02x ", *(p++));
  fprintf(stderr, "\n");
}

std::shared_ptr<Multiplexer> Multiplexer::create(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger,
    const VPNConfig& vpn_config,
    std::shared_ptr<jcu::unio::Resource> io_parent,
    std::shared_ptr<ReliableLayer> reliable
) {
  std::shared_ptr<Multiplexer> instance(new Multiplexer(loop, logger, vpn_config, io_parent, reliable));
  instance->self_ = instance;
  return instance;
}

std::shared_ptr<Multiplexer> Multiplexer::shared() const {
  return self_.lock();
}

Multiplexer::Multiplexer(
    std::shared_ptr<jcu::unio::Loop> loop,
    std::shared_ptr<jcu::unio::Logger> logger,
    const VPNConfig& vpn_config,
    std::shared_ptr<jcu::unio::Resource> io_parent,
    std::shared_ptr<ReliableLayer> reliable
) :
    io_parent_(io_parent),
    loop_(loop),
    logger_(logger),
    vpn_config_(vpn_config),
    reliable_(reliable),
    local_data_packet_id_(0),
    peer_data_packet_id_(0)
{
}

bool Multiplexer::isTLS() const {
  return !vpn_config_.psk_mode;
}

bool Multiplexer::isTCP() const {
  return vpn_config_.protocol == kTransportTcp;
}

int Multiplexer::getRequiredSocketHeader() const {
  return 3;
}

int Multiplexer::getRequiredMessageBufferOffset() const {
  return 1064;
}

std::shared_ptr<jcu::unio::Buffer> Multiplexer::createMessageBuffer() {
  return std::make_shared<BufferWithHeader>(getRequiredMessageBufferOffset(), 65536);
}

int Multiplexer::getRequiredDataPlainBufferOffset() const {
  return 8;
}

void Multiplexer::init(int mtu) {
  mtu_ = mtu;

  send_message_buffer_ = std::make_shared<BufferWithHeader>(getRequiredMessageBufferOffset(), 65536);
  recv_message_buffer_ = std::make_shared<ReceiveBuffer>(65536);
  reliable_->init(self_.lock(), send_message_buffer_);

  // 8 byte packet_id [as offset=8] + plain text
  data_plain_recv_buffer_ = jcu::unio::createFixedSizeBuffer(8 + alignedSize(mtu_, 32));
}

void Multiplexer::connect(jcu::unio::CompletionOnceCallback<jcu::unio::SocketConnectEvent> callback) {
  int rc;

  std::shared_ptr<jcu::unio::Resource> io_parent(io_parent_.lock());
  std::shared_ptr<Multiplexer> self(self_.lock());

  if (vpn_config_.protocol == kTransportTcp) {
    parent_socket_ = jcu::unio::TCPSocket::create(loop_, logger_);
  } else {
    return ;
  }

  auto connect_param = std::make_shared<jcu::unio::SockAddrConnectParam<sockaddr_in>>();
  rc = uv_ip4_addr(vpn_config_.remote_host.c_str(), vpn_config_.remote_port, connect_param->getSockAddr());
  if (rc) {
    jcu::unio::SocketConnectEvent event { jcu::unio::UvErrorEvent {rc, 0} };
    callback(event, *io_parent);
  }
  parent_socket_->connect(connect_param, [self, callback = std::move(callback)](jcu::unio::SocketConnectEvent& event, jcu::unio::Resource& handle) mutable -> void {
    if (event.hasError()) {
      callback(event, handle /* TODO: Hummm... */);
      return ;
    }
    self->parent_socket_->read(self->recv_message_buffer_, [self](jcu::unio::SocketReadEvent& event, jcu::unio::Resource& handle) -> void {
      if (event.hasError()) {
        // TODO: ERROR HANDLING
        self->logger_->logf(jcu::unio::Logger::kLogError, "SOME ERROR... %d / %s", event.error().code(), event.error().what());
        return ;
      }
      self->onRead(dynamic_cast<ReceiveBuffer*>(event.buffer()));
    });

    self->reliable_->doNextOperationAndSendLazyAcks(nullptr);
  });
}

//region Socket Send/Receive

/**
 *  Packet length (16 bits, unsigned) -- TCP only, always sent as
 *      plaintext.  Since TCP is a stream protocol, the packet
 *      length words define the packetization of the stream.
 *
 *  Packet opcode/key_id (8 bits) -- TLS only, not used in pre-shared secret mode.
 *      packet message type, a P_* constant (high 5 bits)
 *      key_id (low 3 bits)
 */

void Multiplexer::onRead(ReceiveBuffer* buffer) {
  ReliableLayer::LazyAckContext ack_context;

  if (isTCP()) {
    while (buffer->remaining() >= 2) {
      const unsigned char* data = (const unsigned char*) buffer->data();
      uint16_t packet_size = protocol::reliable::deserializeUint16(data);
      if (buffer->remaining() >= (2 + packet_size)) {
        buffer->position(buffer->position() + 2);
        handleReceivedPacket(ack_context, packet_size, buffer);
        buffer->position(buffer->position() + packet_size);
      } else {
        break;
      }
    }
    if (buffer->remaining() > 0) {
      buffer->setReadMore();
    } else {
      buffer->clearReadMore();
    }
  } else {
    // UDP is not fragmented
    handleReceivedPacket(ack_context, buffer->remaining(), buffer);
  }

  reliable_->doNextOperationAndSendLazyAcks(&ack_context);
}

void Multiplexer::handleReceivedPacket(ReliableLayer::LazyAckContext& ack_context, uint16_t packet_size, ReceiveBuffer* buffer) {
  const unsigned char* data = (const unsigned char*) buffer->data();
  protocol::reliable::OpCode opcode = protocol::reliable::OpCode::P_DATA_V1; // TODO: IT IS NOT IMPLEMENTED. V1 or V2?
  uint8_t key_id = 0;
  size_t remaining_length = packet_size;

  if (isTLS()) {
    opcode = (protocol::reliable::OpCode)((*data >> 3) & 0x1f);
    key_id = *data & 0x07;
    data++;
    remaining_length--;
  }

  ReliableLayer::UnwrapResult result = reliable_->unwrap(ack_context, opcode, key_id, data, remaining_length, data_plain_recv_buffer_.get());
  if (result & ReliableLayer::kUnwrapData) {
    fprintf(stderr, "UNWRAPPED DATA: %d: ", data_plain_recv_buffer_->remaining());
    dump(data_plain_recv_buffer_->data(), data_plain_recv_buffer_->remaining());
  }
}

void Multiplexer::write(
    uint8_t op_code,
    std::shared_ptr<jcu::unio::Buffer> buffer,
    jcu::unio::CompletionOnceCallback<jcu::unio::SocketWriteEvent> callback
) {
  size_t header_capacity = buffer->position();
  int socket_header_size = getRequiredSocketHeader();
  uint8_t *base_ptr = (uint8_t*) buffer->data();
  uint8_t key_id = reliable_->getKeyId();

  assert (header_capacity >= socket_header_size);

  socket_header_size = 0;
  if (isTLS()) {
    base_ptr--;
    *base_ptr = (op_code << 3) | (key_id & 0x07);
    socket_header_size++;
  }
  if (isTCP()) {
    uint16_t packet_length = socket_header_size + buffer->remaining();
    socket_header_size += 2;
    base_ptr -= 2;
    protocol::reliable::serializeUint16(base_ptr, packet_length);
  }

  buffer->position(buffer->position() - socket_header_size);

  fprintf(stderr, "Multiplexer: write: %d\n", buffer->remaining());
  parent_socket_->write(buffer, std::move(callback));
}

bool Multiplexer::isConnected() const {
  return parent_socket_->isConnected();
}

//endregion

} // namespace transport
} // namespace ovpnc
