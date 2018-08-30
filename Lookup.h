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

#include "AddressInfo.h"
#include "Service.h"
#include "utils/itoa.h"
#include <string>
#include <atomic>

extern "C" {
  const char* dns_strerror(int error);
}

namespace resolver {

class Lookup
{
 private:
  std::string m_hostname;
  Service m_service;
  AddressInfoList m_result;
  int m_error;
  std::atomic_bool m_ready;
  uint32_t m_hints;     // We only store the hash_seed of the hints, because that contains all bits, but is considerately smaller.

 public:
  Lookup(std::string&& hostname, Service const& service, uint32_t hints) :
      m_hostname(std::move(hostname)), m_service(service), m_error(0), m_ready(false), m_hints(hints) { }

  std::string const& get_hostname() const { return m_hostname; }
  Service const& get_service() const { return m_service; }
  uint32_t get_hints() const { return m_hints; }

  void set_result(AddressInfoList&& result)
  {
    m_result = std::move(result);
    m_ready.store(true, std::memory_order_release);
  }

  void set_error(int error)
  {
    m_error = error;
    m_ready.store(true, std::memory_order_release);
  }

  bool is_ready() const { return m_ready.load(std::memory_order_acquire); }
  AddressInfoList const& get_result() const { return m_result; }
  bool success() const { return m_error == 0; }
  char const* get_error() const { return dns_strerror(m_error); }
};

} // namespace resolver