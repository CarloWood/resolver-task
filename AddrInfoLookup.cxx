/**
 * @file
 * @brief Implementation of AddrInfoLookup.
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

#include "sys.h"
#include "AddrInfoLookup.h"

namespace resolver {

std::ostream& operator<<(std::ostream& os, AddrInfoLookup const& addr_info_lookup)
{
  os << "{m_hostname_cache:";
  if (!addr_info_lookup.m_hostname_cache)
    os << "null";
  else
  {
    os << "{node:\"" << addr_info_lookup.m_hostname_cache->str << "\", ";
    if (!addr_info_lookup.m_hostname_cache->is_ready())
      os << "not ready";
    else if (addr_info_lookup.m_hostname_cache->error)
      os << "error:" << addr_info_lookup.m_hostname_cache->error;
    else
      os << "result:" << addr_info_lookup.m_hostname_cache->result;
    os << '}';
  }
  return os << ", m_port:" << addr_info_lookup.m_port << '}';
}

} // namespace resolver
