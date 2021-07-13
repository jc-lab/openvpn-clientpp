#include <iostream>
#include <sstream>
#include <thread>
#include <list>
#include <string>

#include <gtest/gtest.h>

#include "../library/src/transport/transport.h"
#include "../library/src/transport/tcp.h"
#include "../library/src/transport/udp.h"

#define TEMP_SERVER_ADDRESS "127.99.99.99"
#define TEMP_SERVER_PORT    9999

using namespace ovpnc;

enum TcpTestCases {
  kTcpTestServerSideClose,
  kTcpTestClientSideClose
};

class TCPTests : public ::testing::Test {};

std::string listJoinToString(const std::list<std::string>& list) {
  std::string buf;
  for (auto it = list.cbegin(); it != list.cend(); it++) {
    buf += *it + ";";
  }
  return buf;
}

std::shared_ptr<ovpnc::Logger> createLogger() {
  return ovpnc::createDefaultLogger([](auto& line) -> void {
    std::cout << line << std::endl;
  });
}

class TestServer {
 public:
  TcpTestCases test_case_;
  std::shared_ptr<uvw::Loop> loop_;

  TestServer (TcpTestCases test_case) : test_case_(test_case) {
    std::shared_ptr<uvw::Loop> loop(uvw::Loop::create());
    loop_ = loop;

    openTcpServer();

    std::thread th([loop]() -> void {
      loop->run();
    });
    th.detach();
  }

  ~TestServer () {
    loop_->close();
  }

  void openTcpServer() {
    TcpTestCases test_case(test_case_);

    auto tcp_server = loop_->resource<uvw::TCPHandle>();
    tcp_server->on<uvw::ListenEvent>([test_case](auto& listen_event, auto& server) -> void {
      std::shared_ptr<uvw::TCPHandle> client = server.loop().resource<uvw::TCPHandle>();

      std::cout << "[SERVER] NEW CLIENT CONNECTED" << std::endl;

      client->once<uvw::EndEvent>([](auto& event, auto& handle) {
        std::cout << "[SERVER] CLIENT EndEvent" << std::endl;
        handle.close();
      });
      client->once<uvw::ErrorEvent>([](auto& event, auto& handle) {
        std::cout << "[SERVER] CLIENT ErrorEvent : " << event.what() << std::endl;
        handle.close();
      });
      client->once<uvw::DataEvent>([test_case](auto& event, auto& handle) {
        std::cout << "[SERVER] CLIENT DataEvent size=" << event.length << std::endl;
        std::unique_ptr<char[]> data(new char[24]);
        handle.write(std::move(data), 24);
        if (test_case == kTcpTestServerSideClose) {
          handle.shutdown();
        }
      });

      server.accept(*client);
      client->read();
    });
    tcp_server->bind(TEMP_SERVER_ADDRESS, TEMP_SERVER_PORT);
    tcp_server->listen();
  }
};

TEST(TCPTests, ServerSideCloseLogicOrder) {
  std::list<std::string> flowed_logic;

  TestServer test_server(kTcpTestServerSideClose);

  auto loop = uvw::Loop::create();
  auto transport = TransportTCP::create(loop, createLogger());

  {
    uvw::Addr addr { TEMP_SERVER_ADDRESS, TEMP_SERVER_PORT };
    transport->onceConnectEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CONNECTED");
      std::cout << "[TCP CLIENT] Connected" << std::endl;
      transport->read();
      std::unique_ptr<char[]> data(new char[16]);
      transport->write(std::move(data), 16);
    });
    transport->onceCloseEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLOSE");
      std::cout << "[TCP CLIENT] Close" << std::endl;
    });
    transport->onceCleanupEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLEANUP");
      std::cout << "[TCP CLIENT] Cleanup" << std::endl;
    });
    transport->onceErrorEvent([&flowed_logic](Transport* transport, uvw::ErrorEvent& error) -> void {
      flowed_logic.emplace_back("ERROR");
      std::cout << "[TCP CLIENT] Error : " << error.what() << std::endl;
    });
    transport->onDataEvent([&flowed_logic](Transport* transport, Transport::DataEvent& event) -> void {
      std::stringstream s;
      s << "DATA(" << event.length << ")";
      flowed_logic.emplace_back(s.str());
    });
    transport->connect(addr);
  }

  loop->run();

  EXPECT_EQ(listJoinToString(flowed_logic), "CONNECTED;DATA(24);CLOSE;CLEANUP;");
}

TEST(TCPTests, ClientSideCloseLogicOrder) {
  std::list<std::string> flowed_logic;

  TestServer test_server(kTcpTestClientSideClose);

  auto loop = uvw::Loop::create();
  auto transport = TransportTCP::create(loop, createLogger());

  {
    uvw::Addr addr { TEMP_SERVER_ADDRESS, TEMP_SERVER_PORT };
    transport->onceConnectEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CONNECTED");
      std::cout << "[TCP CLIENT] Connected" << std::endl;
      transport->read();
      std::unique_ptr<char[]> data(new char[16]);
      transport->write(std::move(data), 16);
      transport->shutdown();
    });
    transport->onceCloseEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLOSE");
      std::cout << "[TCP CLIENT] Close" << std::endl;
    });
    transport->onceCleanupEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLEANUP");
      std::cout << "[TCP CLIENT] Cleanup" << std::endl;
    });
    transport->onceErrorEvent([&flowed_logic](Transport* transport, uvw::ErrorEvent& error) -> void {
      flowed_logic.emplace_back("ERROR");
      std::cout << "[TCP CLIENT] Error : " << error.what() << std::endl;
    });
    transport->onDataEvent([&flowed_logic](Transport* transport, Transport::DataEvent& event) -> void {
      std::stringstream s;
      s << "DATA(" << event.length << ")";
      flowed_logic.emplace_back(s.str());
    });
    transport->connect(addr);
  }

  loop->run();

  EXPECT_EQ(listJoinToString(flowed_logic), "CONNECTED;DATA(24);CLOSE;CLEANUP;");
}

TEST(TCPTests, ConnectErrorLogicOrder) {
  std::list<std::string> flowed_logic;

  TestServer test_server(kTcpTestClientSideClose);

  auto loop = uvw::Loop::create();
  auto transport = TransportTCP::create(loop, createLogger());

  {
    uvw::Addr addr { TEMP_SERVER_ADDRESS, TEMP_SERVER_PORT + 1 };
    transport->onceConnectEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CONNECTED");
      std::cout << "[TCP CLIENT] Connected" << std::endl;
      transport->read();
      std::unique_ptr<char[]> data(new char[16]);
      transport->write(std::move(data), 16);
      transport->shutdown();
    });
    transport->onceCloseEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLOSE");
      std::cout << "[TCP CLIENT] Close" << std::endl;
    });
    transport->onceCleanupEvent([&flowed_logic](Transport* transport) -> void {
      flowed_logic.emplace_back("CLEANUP");
      std::cout << "[TCP CLIENT] Cleanup" << std::endl;
    });
    transport->onceErrorEvent([&flowed_logic](Transport* transport, uvw::ErrorEvent& error) -> void {
      flowed_logic.emplace_back("ERROR");
      std::cout << "[TCP CLIENT] Error : " << error.what() << std::endl;
    });
    transport->onDataEvent([&flowed_logic](Transport* transport, Transport::DataEvent& event) -> void {
      std::stringstream s;
      s << "DATA(" << event.length << ")";
      flowed_logic.emplace_back(s.str());
    });
    transport->connect(addr);
  }

  loop->run();

  EXPECT_EQ(listJoinToString(flowed_logic), "ERROR;CLOSE;CLEANUP;");
}
