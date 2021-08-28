/**
 * @file	openssl_tls_layer.cc
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "openssl_tls_layer.h"

#include "../transport/reliable_layer.h"

namespace ovpnc {
namespace openssl {

OpenSslTlsLayer::OpenSslTlsLayer(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<transport::ReliableLayer> parent,
    std::shared_ptr<SSL_CTX> ssl_ctx
) :
    TlsLayer(std::move(parent), std::move(logger)),
    ssl_ctx_(std::move(ssl_ctx)),
    ssl_(nullptr),
    ssl_bio_(nullptr),
    app_bio_(nullptr)
{
  logger_->logf(Logger::kLogDebug, "OpenSslTlsLayer: Construct");
}

OpenSslTlsLayer::~OpenSslTlsLayer() {
  logger_->logf(Logger::kLogDebug, "OpenSslTlsLayer: Deconstruct");
}

std::shared_ptr<OpenSslTlsLayer> OpenSslTlsLayer::create(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<transport::ReliableLayer> parent,
    std::shared_ptr<SSL_CTX> ssl_ctx
) {
  std::shared_ptr<OpenSslTlsLayer> instance(new OpenSslTlsLayer(std::move(logger), std::move(parent), std::move(ssl_ctx)));
  instance->self_ = instance;
  return std::move(instance);
}

void OpenSslTlsLayer::tlsReset() {
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

  SSL_set_connect_state(ssl_.get());
}

bool OpenSslTlsLayer::tlsOperation(TlsOp op) {
  std::shared_ptr<transport::ReliableLayer> parent(parent_.lock());
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
        Transport::DataEvent data_event {
            0,
            std::move(buf),
            (unsigned int) ssl_rc,
            {},
            false
        };
        logger_->logf(Logger::kLogDebug, "SSL Inbound: size=%d", ssl_rc);
        if (data_handler_) {
          data_handler_(this, data_event);
        }
      } while (true);
      break;
    default:tlsErrorEmit(-1);
      return false;
  }
  return true;
}

void OpenSslTlsLayer::feedInboundCipherText(const unsigned char *raw_payload, int length) {
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

bool OpenSslTlsLayer::tlsErrorEmit(int ssl_rc) {
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

void OpenSslTlsLayer::write(std::unique_ptr<char[]> data, unsigned int len) {
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

std::shared_ptr<uvw::Loop> OpenSslTlsLayer::getLoop() {
  return parent_.lock()->getLoop();
}

void OpenSslTlsLayer::connect(const sockaddr *addr) {
  // nothing
}
void OpenSslTlsLayer::connect(const uvw::Addr &addr) {
  // nothing
}

void OpenSslTlsLayer::read() {
  // nothing
}

void OpenSslTlsLayer::shutdown() {
  // nothing
}
void OpenSslTlsLayer::close() {
  // nothing
}

bool OpenSslTlsLayer::tls1Prf(
    const uint8_t *seed,
    int seed_len,
    const uint8_t *secret,
    int secret_len,
    uint8_t *output,
    int output_len
) const {
  bool ret = false;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr);
  if (!pctx) {
    return false;
  }
  do {
    if (!EVP_PKEY_derive_init(pctx)) {
      break;
    }
    if (!EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1())) {
      break;
    }
    if (!EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, secret_len)) {
      break;
    }
    if (!EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seed_len)) {
      break;
    }
    size_t out_len = output_len;
    if (!EVP_PKEY_derive(pctx, output, &out_len)) {
      break;
    }
    if (out_len != output_len) {
      break;
    }
    ret = true;
  } while(0);
  EVP_PKEY_CTX_free(pctx);
  return ret;
}

} // namespace openssl
} // namespace ovpnc
