/**
 * resolver-task -- AIStatefulTask submodule - asynchronous hostname resolver.
 *
 * @file
 * @brief Declaration of class Service.
 *
 * @Copyright (C) 2019  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of resolver-task.
 *
 * Resolver-task is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Resolver-task is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with resolver-task.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "utils/macros.h"
#include "debug.h"
#include <netinet/in.h>         // Protocol numbers.
#include <string_view>
#include <array>
#include <cstring>
#include <iosfwd>

// Should be defined in netinet/in.h, but not necessarily.
// See /etc/protocols for the correct values.
#ifndef IPPROTO_DDP
#define IPPROTO_DDP 37
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

namespace resolver {

using in_proto_t = uint8_t;     // A type for protocol numbers (IPPROTO_*).

constexpr size_t max_service_name_length = 24;

class Service
{
 private:
  in_proto_t m_protocol;
  char m_name[max_service_name_length + 1];     // Service name as C string (null terminated).
                                                // The first 7 bytes are used as hash seed and must always be initialized (with trailing 0's).
 public:
  Service() { }
  Service(char const* name, in_proto_t protocol = 0);

  // Only the first 7 bytes of a service name are used in the hash.
  uint64_t hash() const { uint64_t hashed_part; std::memcpy(&hashed_part, this, 8); return hashed_part; }

  in_proto_t protocol() const { return m_protocol; }
  char const* name() const { return m_name; }

  friend std::ostream& operator<<(std::ostream& os, Service const& service);
};

} // namespace resolver
