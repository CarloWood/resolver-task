/**
 * resolver-task -- AIStatefulTask submodule - asynchronous hostname resolver.
 *
 * @file
 * @brief Definition of class Service.
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

#include "sys.h"
#include "Service.h"
#include <iostream>
#include <cstring>

namespace resolver {

Service::Service(char const* name, in_proto_t protocol) : m_protocol(protocol)
{
  std::strncpy(m_name, name, max_service_name_length);
}

std::ostream& operator<<(std::ostream& os, Service const& service)
{
  os << "Service:{name:\"" << service.name() << "\", protocol:" << service.protocol() << '}';
  return os;
}

} // namespace resolver
