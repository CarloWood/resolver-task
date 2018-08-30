#pragma once

#include "utils/macros.h"
#include "debug.h"
#include <string_view>
#include <array>
#include <cstring>
#include <iosfwd>

namespace resolver {

constexpr size_t max_service_name_length = 24;

class Service
{
 private:
  char m_name[max_service_name_length + 1];     // Service name as C string (null terminated).
                                                // The first 8 bytes are used as hash seed and must always be initialized (with trailing 0's).
 public:
  // Numeric port (no service name is known or needs to be looked up).
  Service() { std::memset(m_name, 0, 8); }

  Service(std::string_view service_name)
  {
    ASSERT(service_name.size() <= max_service_name_length);
    std::memset(m_name, 0, 8);
    service_name.copy(m_name, max_service_name_length);
    m_name[std::min(max_service_name_length, service_name.size())] = '\0';
  }

  Service(Service const& service)
  {
    std::memcpy(m_name, service.m_name, 8);
    if (!is_numeric())
      strcpy(m_name, service.m_name);
  }

  Service& operator=(Service const& service)
  {
    std::memcpy(m_name, service.m_name, 8);
    if (!is_numeric())
      strcpy(m_name, service.m_name);
    return *this;
  }

  // The format in which the service is stored.
  bool is_numeric() const { return AI_LIKELY(!m_name[0]); }

  // If is_numeric() returns true then this will return an empty string.
  char const* get_name() const { return m_name; }

  // A numeric port is not hashed because it is not part of a DNS lookup.
  // Only the first 8 bytes of a service name are used in the hash.
  uint64_t hash_seed() const { uint64_t hashed_part; std::memcpy(&hashed_part, m_name, 8); return hashed_part; }

  // Returns true if this Service and other are different enough to be stored separately in the cache.
  // Note it does NOT take numeric port numbers into account (we don't want to do another lookup when
  // only the port number differs); this is why we cannot rely on a numeric port number to have any
  // meaning for us and port numbers are not stored in a Service object.
  bool is_cache_equal_to(Service const& other) const
  {
    // It is always safe to call strcmp because "numeric" services contain empty strings.
    // Nevertheless we test is_numeric first because they are just very likely to be both true.
    return (is_numeric() && other.is_numeric()) || !std::strcmp(m_name, other.m_name);
  }

  friend bool operator<(Service const& service1, Service const& service2);
  friend std::ostream& operator<<(std::ostream& os, Service const& service);
};

} // namespace resolver
