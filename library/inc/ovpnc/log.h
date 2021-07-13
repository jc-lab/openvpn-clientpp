/**
 * @file	log.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_LOG_H_
#define OVPNC_LOG_H_

#include <memory>
#include <string>
#include <cstdarg>
#include <functional>

namespace ovpnc {

typedef std::function<void(const std::string &log)> LogWriter_t;

class Logger {
 public:
  enum LogLevel {
    kLogTrace,
    kLogDebug,
    kLogInfo,
    kLogWarn,
    kLogError
  };

  virtual void logf(LogLevel level, const char *format, ...) = 0;
};

std::shared_ptr<Logger> createDefaultLogger(const LogWriter_t &writer);

} // namespace ovpnc

#endif //OVPNC_LOG_H_
