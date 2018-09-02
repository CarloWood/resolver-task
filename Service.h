#pragma once

#include "utils/macros.h"
#include "debug.h"
#include <netinet/in.h>         // Protocol numbers; in_port_t
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
