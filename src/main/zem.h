// Copyright 2023 Justin Hu
//
// This file is part of Zootronian Encrypted Messaging.
//
// Zootronian Encrypted Messaging is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// Zootronian Encrypted Messaging is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Zootronian Encrypted Messaging. If not, see
// <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "sodium.h"

namespace zem {
class SocketException : public std::exception {
 public:
  SocketException() noexcept = default;
  SocketException(SocketException const &) noexcept = default;
  SocketException(SocketException &&) noexcept = default;

  ~SocketException() noexcept override = default;

  SocketException &operator=(SocketException const &) noexcept = default;
  SocketException &operator=(SocketException &&) noexcept = default;

  char const *what() const noexcept = 0;
};

/**
 * interface definition for a socket; implementation is platform-specific
 */
class Socket {
 public:
  Socket() noexcept = default;
  Socket(Socket const &) noexcept = delete;
  Socket(Socket &&) noexcept = default;

  virtual ~Socket() noexcept = default;

  Socket &operator=(Socket const &) noexcept = delete;
  Socket &operator=(Socket &&) noexcept = default;

  virtual void send(void const *source, size_t length) = 0;
  virtual void recv(void *destination, size_t length) = 0;
};

/**
 * interface definition for a server (passive) socket; implementation is again,
 * platform-specific
 */
class ServerSocket {
 public:
  ServerSocket() noexcept = default;
  ServerSocket(ServerSocket const &) noexcept = delete;
  ServerSocket(ServerSocket &&) noexcept = default;

  virtual ~ServerSocket() noexcept = default;

  ServerSocket &operator=(ServerSocket const &) noexcept = delete;
  ServerSocket &operator=(ServerSocket &&) noexcept = default;

  virtual std::unique_ptr<Socket> accept() = 0;
};

class CryptoException : public std::exception {
 public:
  explicit CryptoException(std::string const &message) noexcept;
  CryptoException(CryptoException const &) noexcept = default;
  CryptoException(CryptoException &&) noexcept = default;

  ~CryptoException() noexcept override = default;

  CryptoException &operator=(CryptoException const &) noexcept = default;
  CryptoException &operator=(CryptoException &&) noexcept = default;

  char const *what() const noexcept override;

 private:
  std::string message;
};

/**
 * A connection endpoint; non-passive endpoints are symmetric
 */
class Endpoint final {
 public:
  explicit Endpoint(std::string const &password,
                    std::unique_ptr<Socket> &&socket);
  Endpoint(Endpoint const &) noexcept = delete;
  Endpoint(Endpoint &&) noexcept = default;

  ~Endpoint() noexcept;

  Endpoint &operator=(Endpoint const &) noexcept = delete;
  Endpoint &operator=(Endpoint &&) noexcept = default;

  Endpoint &operator<<(uint8_t);
  Endpoint &operator<<(uint16_t);
  Endpoint &operator<<(uint32_t);
  Endpoint &operator<<(uint64_t);

  Endpoint &operator<<(int8_t);
  Endpoint &operator<<(int16_t);
  Endpoint &operator<<(int32_t);
  Endpoint &operator<<(int64_t);

  Endpoint &operator<<(bool);

  Endpoint &operator<<(float);
  Endpoint &operator<<(double);

  Endpoint &operator<<(char);

  Endpoint &operator>>(uint8_t &);
  Endpoint &operator>>(uint16_t &);
  Endpoint &operator>>(uint32_t &);
  Endpoint &operator>>(uint64_t &);

  Endpoint &operator>>(int8_t &);
  Endpoint &operator>>(int16_t &);
  Endpoint &operator>>(int32_t &);
  Endpoint &operator>>(int64_t &);

  Endpoint &operator>>(float &);
  Endpoint &operator>>(double &);

  Endpoint &operator>>(char &);

  void flush();

 private:
  static constexpr uint64_t PACKET_SIZE = 4096;
  static constexpr uint64_t BUFFER_SIZE =
      PACKET_SIZE - crypto_secretstream_xchacha20poly1305_ABYTES -
      sizeof(uint64_t);

  std::unique_ptr<Socket> socket;
  crypto_secretstream_xchacha20poly1305_state sendState;
  std::vector<uint8_t> sendBuffer;
  crypto_secretstream_xchacha20poly1305_state recvState;
  std::vector<uint8_t> recvBuffer;
};

/**
 * A server
 */
class Server final {
 public:
  Server(std::string const &password,
         std::unique_ptr<ServerSocket> &&socket) noexcept;
  Server(Server const &) noexcept = delete;
  Server(Server &&) noexcept = default;

  ~Server() noexcept = default;

  Server &operator=(Server const &) noexcept = delete;
  Server &operator=(Server &&) noexcept = default;

  Endpoint accept();

 private:
  std::string const &password;
  std::unique_ptr<ServerSocket> socket;
};
}  // namespace zem
