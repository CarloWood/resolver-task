/**
 * @file
 * @brief Resolve an IP number. Declaration of class NameInfoLookup.
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

#include "DnsResolver.h"

extern "C" {
  const char* dns_strerror(int error);
}

namespace resolver {

// Represents a running GetNameInfo lookup.
class NameInfoLookup
{
  using AddressCacheEntry = DnsResolver::AddressCacheEntry;

 private:
   std::shared_ptr<AddressCacheEntry> m_address_cache;

 public:
  NameInfoLookup(std::shared_ptr<AddressCacheEntry> const& address_cache) :
      m_address_cache(address_cache) { }

  NameInfoLookup(std::shared_ptr<AddressCacheEntry>&& address_cache) :
      m_address_cache(std::move(address_cache)) { }

  std::string const& get_arpaname() const { return m_address_cache->arpa_str; }

  // Return the events::Server that will get triggered after is_ready is set.
  auto& event_server() const { return m_address_cache->event_server(); }

  // You shouldn't really use this as it is polling. Use event_server().request() instead to get notified.
  bool is_ready() const { return m_address_cache->is_ready(); }

  bool success() const
  {
    // Don't call success() when is_ready() doesn't return true (you should request a callback from the event_server()).
    // If you're using GetNameInfo: only call success() from the callback or parent (after successful finish of the child).
    ASSERT(m_address_cache->is_ready());
    return m_address_cache->error == 0;
  }
  std::string const& get_result() const
  {
    // Don't call get_result() when success() doesn't return true.
    ASSERT(!m_address_cache->error);
    return m_address_cache->result;
  }
  char const* get_error() const
  {
    // Don't call get_result() when success() doesn't return false.
    ASSERT(m_address_cache->error);
    return dns_strerror(m_address_cache->error);
  }
};

} // namespace resolver
