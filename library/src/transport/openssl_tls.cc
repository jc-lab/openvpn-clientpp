/**
 * @file	openssl_tls.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "openssl_tls.h"

#include "reliable_layer.h"

namespace ovpnc {
namespace transport {

struct SSL_Deleter {
  void operator()(SSL *p) {
    SSL_shutdown(p);
    SSL_free(p);
  }
};
struct SSL_CTX_Deleter {
  void operator()(SSL_CTX *p) { SSL_CTX_free(p); }
};
struct BIO_NO_Deleter {
  void operator()(BIO *p) {
    // DO NOT RELEASE!
    // Automatically release by SSL_free with SSL_MODE_RELEASE_BUFFERS option
    // SSL_free:
    //   BIO_free_all(s->wbio);
    //   BIO_free_all(s->rbio);
  }
};

class OpenSslTlsLayerImpl : public OpenSslTlsLayer {
 private:
  std::weak_ptr<OpenSslTlsLayerImpl> self_;

  SslCtxCustomizer_t ssl_ctx_customizer_;

  std::unique_ptr<SSL_CTX, SSL_CTX_Deleter> ssl_ctx_;
  std::unique_ptr<SSL, SSL_Deleter> ssl_;

  std::unique_ptr<BIO, BIO_NO_Deleter> ssl_bio_;
  std::unique_ptr<BIO, BIO_NO_Deleter> app_bio_;

  OpenSslTlsLayerImpl(std::shared_ptr<ReliableLayer> parent, std::shared_ptr<Logger> logger) :
      OpenSslTlsLayer(std::move(parent), std::move(logger)),
      ssl_(nullptr),
      ssl_ctx_(nullptr),
      ssl_bio_(nullptr),
      app_bio_(nullptr),
      ssl_ctx_customizer_(nullptr) {
    logger_->logf(Logger::kLogDebug, "OpenSslTls: Construct");
  }

  static int tlsVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    return preverify_ok;
  }

 public:
  static std::shared_ptr<OpenSslTlsLayerImpl> create(std::shared_ptr<ReliableLayer> parent,
                                                     std::shared_ptr<Logger> logger) {
    std::shared_ptr<OpenSslTlsLayerImpl> instance(new OpenSslTlsLayerImpl(std::move(parent), std::move(logger)));
    instance->self_ = instance;
    return std::move(instance);
  }

  void setSslCtxCustomizer(const SslCtxCustomizer_t &ssl_ctx_customizer) override {
    ssl_ctx_customizer_ = ssl_ctx_customizer;
  }

  void tlsInit() override {
    ssl_ctx_.reset(SSL_CTX_new(TLS_client_method()));
    if (!ssl_ctx_) {
      return;
    }

    SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    unsigned int ssl_ctx_mode =
        SSL_MODE_AUTO_RETRY |
            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
            SSL_MODE_ENABLE_PARTIAL_WRITE |
            SSL_MODE_RELEASE_BUFFERS;

    SSL_CTX_set_mode(
        ssl_ctx_.get(),
        ssl_ctx_mode
    );

    if (ssl_ctx_customizer_) {
      ssl_ctx_customizer_(ssl_ctx_.get());
    }
  }

  void tlsReset() override {
    BIO *ssl_bio = nullptr;
    BIO *app_bio = nullptr;
    int ssl_rc;

    ssl_.reset(SSL_new(ssl_ctx_.get()));
    if (!ssl_) {
      return;
    }

    ssl_rc = BIO_new_bio_pair(&ssl_bio, 0, &app_bio, 0);
    if (tlsErrorEmit(ssl_rc)) {
      return;
    }

    SSL_set_bio(ssl_.get(), ssl_bio, ssl_bio);

    ssl_bio_.reset(ssl_bio);
    app_bio_.reset(app_bio);

    SSL_set_verify(
        ssl_.get(),
        SSL_VERIFY_NONE/*  | SSL_VERIFY_PEER */,
        tlsVerifyCallback
    );

    SSL_set_connect_state(ssl_.get());
  }

  bool tlsOperation(TlsOp op) override {
    std::shared_ptr<ReliableLayer> parent(parent_.lock());
    int ssl_rc;
    int pending;

    switch (op) {
      case kTlsOpHandshake:ssl_rc = SSL_do_handshake(ssl_.get());
        state_ = kHandshakeState;
        if (tlsErrorEmit(ssl_rc)) {
          state_ = kHandshakeFailedState;
          return false;
        }
        if (ssl_rc == 1) {
          postHandshaked();
        }
        break;
      case kTlsOpWriteToRemote:
        while ((pending = BIO_pending(app_bio_.get())) > 0) {
          protocol::reliable::UniqueCharArrPacketWriter packet_writer{parent->getProtocolConfig()};
          protocol::reliable::ControlV1Payload payload{protocol::reliable::P_CONTROL_V1};
          parent->initControlV1PayloadToSend(&payload);
          packet_writer.prepare(&payload, pending);

          logger_->logf(Logger::kLogDebug, "OpenSslTls: operation: BIO_pending=%d", pending);
          ssl_rc = BIO_read(app_bio_.get(), packet_writer.getAppendDataBuffer(), pending);
          logger_->logf(Logger::kLogDebug, "OpenSslTls: operation: BIO_read=%d", pending);
          if (tlsErrorEmit(ssl_rc)) {
            return false;
          }

          packet_writer.setAppendDataSize(ssl_rc);
          packet_writer.write(0);
          parent->writeRawPacket(std::move(packet_writer.buffer), packet_writer.getPacketLength());
        }
        break;
      case kTlsOpReadFromRemote:
        do {
          const int buf_size = 16384;
          std::unique_ptr<char[]> buf(new char[buf_size]);
          ssl_rc = SSL_read(ssl_.get(), buf.get(), buf_size);
          if (ssl_rc == 0) break;
          if (tlsErrorEmit(ssl_rc)) {
            return false;
          }
          if (ssl_rc < 0) break;
          Transport::DataEvent data_event{
              std::move(buf),
              (unsigned int) ssl_rc,
              {},
              false
          };
          logger_->logf(Logger::kLogDebug, "SSL Inbound: size=%d", ssl_rc);
          // data_handler_(this, data_event);
        } while (true);
        break;
      default:tlsErrorEmit(-1);
        return false;
    }
    return true;
  }

  void feedInboundCipherText(const unsigned char *raw_payload, int length) override {
    int proceed_length = 0;
    for (int offset = 0; offset < length; offset += proceed_length) {
      TlsOp tls_op;
      proceed_length = BIO_write(app_bio_.get(), raw_payload + offset, length - offset);
      tls_op = SSL_is_init_finished(ssl_.get()) ? kTlsOpReadFromRemote : kTlsOpHandshake;
      if (!tlsOperation(tls_op)) {
        return;
      }
    }
  }

  bool tlsErrorEmit(int ssl_rc) {
    int ssl_error;
    char msg_buf[128];

    if (ssl_rc > 0) {
      return false;
    }

    ssl_error = SSL_get_error(ssl_.get(), ssl_rc);
    switch (ssl_error) {
      case SSL_ERROR_WANT_WRITE:logger_->logf(Logger::kLogDebug, "SSL_ERROR_WANT_WRITE");
        break;
      case SSL_ERROR_WANT_READ:
        if (tlsOperation(kTlsOpWriteToRemote)) {
          return false;
        }
        break;
      default:;
    }

    msg_buf[0] = 0;
    ERR_error_string_n(ssl_rc, msg_buf, sizeof(msg_buf));

    logger_->logf(Logger::kLogError, "OpenSslTls: tls error: rc=%d, ssl_err=%d: %s", ssl_rc, ssl_error, msg_buf);

    if (error_handler_) {
      uvw::ErrorEvent error_event{UV__EIO};
      error_handler_(this, error_event);
    }

    shutdown();

    return true;
  }

  void write(std::unique_ptr<char[]> data, unsigned int len) {
    int ssl_rc;
    int offset;
    int proceed_length = 0;
    for (offset = 0; offset < len; offset += proceed_length) {
      ssl_rc = SSL_write(ssl_.get(), data.get() + offset, len - offset);
      if (tlsErrorEmit(ssl_rc)) {
        return;
      }
      proceed_length = ssl_rc;
      if (!tlsOperation(kTlsOpWriteToRemote)) {
        return;
      }
    }
  }

  std::shared_ptr<uvw::Loop> getLoop() override {
    return parent_.lock()->getLoop();
  }

  void connect(const sockaddr *addr) override {
    // nothing
  }
  void connect(const uvw::Addr &addr) override {
    // nothing
  }

  void read() override {
    // nothing
  }

  void shutdown() override {
    // nothing
  }
  void close() override {
    // nothing
  }
};

std::shared_ptr<OpenSslTlsLayer> createOpenSslTlsLayer(std::shared_ptr<ReliableLayer> parent,
                                                       std::shared_ptr<Logger> logger) {
  return std::move(OpenSslTlsLayerImpl::create(std::move(parent), std::move(logger)));
}

} // namespace transport
} // namespace ovpnc
