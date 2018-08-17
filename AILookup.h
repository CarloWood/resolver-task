/**
 * @file
 * @brief Resolve a hostname. Declaration of class AILookup.
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

#include "evio/SocketAddressList.h"
#include <string>
#include <atomic>

class AILookup
{
 private:
  std::string m_hostname;
  std::string m_servicename;
  evio::SocketAddressList m_result;
  std::atomic_bool m_ready;

 public:
  AILookup(std::string&& hostname, std::string&& servicename) : m_hostname(std::move(hostname)), m_servicename(std::move(servicename)) { }

  std::string const& get_hostname() const { return m_hostname; }
  std::string const& get_servicename() const { return m_servicename; }

  void set_result(evio::SocketAddressList&& result)
  {
    m_result = std::move(result);
    m_ready.store(true, std::memory_order_release);
  }

  bool is_ready() const { return m_ready.load(std::memory_order_acquire); }
  evio::SocketAddressList const& get_result() const { return m_result; }
};
