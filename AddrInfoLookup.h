/**
 * @file
 * @brief Resolve a hostname. Declaration of class AddrInfoLookup.
 *
 * @Copyright (C) 2018  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "Resolver.h"

extern "C" {
  const char* dns_strerror(int error);
}

namespace resolver {

// Represents a running GetAddrInfo lookup.
class AddrInfoLookup
{
  using HostnameCacheEntry = Resolver::HostnameCacheEntry;

 private:
   std::shared_ptr<HostnameCacheEntry> m_hostname_cache;
   in_port_t m_port;

 public:
  AddrInfoLookup(std::shared_ptr<HostnameCacheEntry> const& hostname_cache, in_port_t port) :
      m_hostname_cache(hostname_cache), m_port(port) { }

  AddrInfoLookup(std::shared_ptr<HostnameCacheEntry>&& hostname_cache, in_port_t port) :
      m_hostname_cache(std::move(hostname_cache)), m_port(port) { }

  std::string const& get_hostname() const { return m_hostname_cache->str; }
  uint32_t get_hints() const { return m_hostname_cache->hints; }

  // Accessor.
  in_port_t get_port() const { return m_port; }

  // Return the events::Server that will get triggered after is_ready is set.
  auto& event_server() const { return m_hostname_cache->event_server(); }

  // You shouldn't really use this as it is polling. Use event_server().request() instead to get notified.
  bool is_ready() const { return m_hostname_cache->is_ready(); }

  bool success() const
  {
    // Don't call success() when is_ready() doesn't return true (you should request a callback from the event_server()).
    // If you're using GetAddrInfo: only call success() from the callback or parent (after successful finish of the child).
    ASSERT(m_hostname_cache->is_ready());
    return m_hostname_cache->error == 0;
  }
  AddressInfoList const& get_result() const
  {
    // Don't call get_result() when success() doesn't return true.
    ASSERT(!m_hostname_cache->error);
    return m_hostname_cache->result;
  }
  char const* get_error() const
  {
    // Don't call get_result() when success() doesn't return false.
    ASSERT(m_hostname_cache->error);
    return dns_strerror(m_hostname_cache->error);
  }

  // Return the hostname that is the lookup for.
  std::string const& hostname() const { return m_hostname_cache->str; }

  // Set some custom error.
  void set_error_empty() { m_hostname_cache->set_error_empty(); }

  // Support writing to ostream.
  friend std::ostream& operator<<(std::ostream& os, AddrInfoLookup const& addr_info_lookup);
};

} // namespace resolver
