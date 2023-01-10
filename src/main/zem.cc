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

#include "zem.h"

#include <array>
#include <utility>

using namespace std;

namespace zem {
CryptoException::CryptoException(string const &message_) noexcept
    : message(message_) {}
char const *CryptoException::what() const noexcept { return message.c_str(); }

Endpoint::Endpoint(string const &password_, unique_ptr<Socket> &&socket_)
    : socket(move(socket_)) {
  sendBuffer.reserve(Endpoint::BUFFER_SIZE);
  recvBuffer.reserve(Endpoint::BUFFER_SIZE);

  // setup sending state
  array<unsigned char, crypto_pwhash_SALTBYTES> sendSalt;
  randombytes_buf(sendSalt.data(), sendSalt.size());
  socket->send(sendSalt.data(), sendSalt.size());

  array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES> sendKey;
  if (crypto_pwhash(
          sendKey.data(), sendKey.size(), password_.c_str(), password_.size(),
          sendSalt.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    throw runtime_error("crypto_pwhash ran out of memory");
  }

  array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>
      sendHeader;
  crypto_secretstream_xchacha20poly1305_init_push(&sendState, sendHeader.data(),
                                                  sendKey.data());
  socket->send(sendHeader.data(), sendHeader.size());

  // setup receiving state
  array<unsigned char, crypto_pwhash_SALTBYTES> recvSalt;
  socket->recv(recvSalt.data(), recvSalt.size());

  array<unsigned char, crypto_secretstream_xchacha20poly1305_KEYBYTES> recvKey;
  if (crypto_pwhash(
          recvKey.data(), recvKey.size(), password_.c_str(), password_.size(),
          recvSalt.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    throw runtime_error("crypto_pwhash ran out of memory");
  }

  array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES>
      recvHeader;
  socket->recv(recvHeader.data(), recvHeader.size());
  if (crypto_secretstream_xchacha20poly1305_init_pull(
          &recvState, recvHeader.data(), recvKey.data()) != 0) {
    throw CryptoException("invalid password");
  }
}

Server::Server(string const &password_,
               unique_ptr<ServerSocket> &&socket_) noexcept
    : password(password_), socket(move(socket_)) {}

Endpoint Server::accept() { return Endpoint(password, socket->accept()); }
}  // namespace zem
