/**
 * @file	state_machine.h
 * @author	Joseph Lee <joseph@jc-lab.net>
 * @date	2021-07-28
 * @copyright Copyright (C) 2021 jc-lab. All rights reserved.
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_STATE_MACHINE_H_
#define OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_STATE_MACHINE_H_


namespace ovpnc {
namespace transport {

class ParentMachine {
 public:
  void changeState();
};

class StateMachine {
 public:
  bool process();
};

} // namespace transport
} // namespace ovpn

#endif //OPENVPN_CLIENTPP_LIBRARY_SRC_TRANSPORT_STATE_MACHINE_H_
