/**
 * @file	transport.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-08
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_TRANSPORT_TRANSPORT_H_
#define OVPNC_SRC_TRANSPORT_TRANSPORT_H_

#include <memory>
#include <string>

#include <uvw/stream.h>

#include "../protocol/reliable.h"

namespace ovpnc {
namespace transport {

class Transport {
 protected:
  std::shared_ptr<void> user_data_;
  protocol::reliable::ProtocolTransportConfig protocol_config_;

 public:
  struct DataEvent {
    /**
     * 0 = transport
     * 0x11 = tls
     */
    int type;

    std::unique_ptr<char[]> data;
    unsigned int length;

    /**
     * UDP-Only
     */
    uvw::Addr sender;

    /**
     * UDP-Only
     */
    bool partial;

    DataEvent() :
    type(0), length(0), sender({}), partial(false)
    {}

    DataEvent(int arg_type, std::unique_ptr<char[]> arg_data, unsigned int arg_length, uvw::Addr arg_sender = {}, bool arg_partial = false)
        : type(arg_type), data(std::move(arg_data)), length(arg_length), sender(std::move(arg_sender)), partial(arg_partial)
        {}
  };

  typedef std::function<void(Transport *transport)> ConnectEventHandler_t;
  typedef std::function<void(Transport *transport, DataEvent &event)> DataEventHandler_t;
  typedef std::function<void(Transport *transport)> CloseEventHandler_t;
  typedef std::function<void(Transport *transport, uvw::ErrorEvent &event)> ErrorEventHandler_t;
  typedef std::function<void(Transport *transport)> CleanupHandler_t;

  Transport() :
      user_data_(nullptr) {}

  virtual ~Transport() = default;

  virtual std::shared_ptr<uvw::Loop> getLoop() = 0;

  template<typename R = void>
  std::shared_ptr<R> data() const {
    return std::static_pointer_cast<R>(user_data_);
  }
  void data(std::shared_ptr<void> user_data) {
    user_data_ = std::move(user_data);
  }

  const protocol::reliable::ProtocolTransportConfig *getProtocolConfig() {
    return &protocol_config_;
  }

  virtual void connect(const sockaddr *addr) = 0;
  virtual void connect(const uvw::Addr &addr) = 0;
  virtual void read() = 0;
  virtual void write(std::unique_ptr<char[]> data, unsigned int len) = 0;
  virtual void onceConnectEvent(const ConnectEventHandler_t &handler) = 0;
  virtual void onDataEvent(const DataEventHandler_t &handler) = 0;
  virtual void onceCloseEvent(const CloseEventHandler_t &handler) = 0;
  virtual void onceErrorEvent(const ErrorEventHandler_t &handler) = 0;
  virtual void onceCleanupEvent(const CleanupHandler_t &handler) = 0;
  virtual void shutdown() = 0;
  virtual void close() = 0;
};

} // namespace transport
} // namespace ovpnc

#endif //OVPNC_SRC_TRANSPORT_TRANSPORT_H_
