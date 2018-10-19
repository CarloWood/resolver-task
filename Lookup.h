/**
 * @file
 * @brief Resolve a hostname. Declaration of class Lookup.
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

class Lookup
{
  using HostnameCacheEntry = Resolver::HostnameCacheEntry;

 private:
   std::shared_ptr<HostnameCacheEntry> m_hostname_cache;
   in_port_t m_port;

 public:
  Lookup(std::shared_ptr<HostnameCacheEntry> const& hostname_cache, in_port_t port) :
      m_hostname_cache(hostname_cache), m_port(port) { }

  Lookup(std::shared_ptr<HostnameCacheEntry>&& hostname_cache, in_port_t port) :
      m_hostname_cache(std::move(hostname_cache)), m_port(port) { }

  std::string const& get_hostname() const { return m_hostname_cache->str; }
  uint32_t get_hints() const { return m_hostname_cache->hints; }

  bool is_ready() const { return m_hostname_cache->is_ready(); }
  AddressInfoList const& get_result() const { ASSERT(!m_hostname_cache->error); return m_hostname_cache->result; }
  in_port_t get_port() const { return m_port; }
  bool success() const { return m_hostname_cache->error == 0; }
  char const* get_error() const { return dns_strerror(m_hostname_cache->error); }
  auto& event_server() const { return m_hostname_cache->event_server(); }
};

} // namespace resolver
