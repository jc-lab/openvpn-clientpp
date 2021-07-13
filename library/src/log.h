/**
 * @file	log.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-09
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef OVPNC_SRC_LOG_H_
#define OVPNC_SRC_LOG_H_

#include <ovpnc/log.h>

namespace ovpnc {
namespace intl {

std::shared_ptr<Logger> createNullLogger();

} // namespace intl
} // namespace ovpnc

#endif //OPVPNC_SRC_LOG_H_
