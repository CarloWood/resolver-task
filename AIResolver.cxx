/**
 * @file
 * @brief Implementation of AIResolver.
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
#include "AIResolver.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"

namespace {
SingletonInstance<AIResolver> dummy __attribute__ ((__unused__));
} // namespace

std::shared_ptr<AILookup> AIResolver::do_request(std::string&& hostname, std::string&& servicename)
{
  DoutEntering(dc::notice, "AIResolver::do_request(\"" << hostname << "\", \"" << servicename << "\")");
  std::shared_ptr<AILookup> handle;
  {
    utils::Allocator<AILookup, utils::NodeMemoryPool> node_allocator(m_node_memory_pool);
    handle = std::allocate_shared<AILookup>(node_allocator, std::move(hostname), std::move(servicename));
  }

  Dout(dc::notice, "All done...");

  // Fake a lookup for now.
  evio::SocketAddress sa1("127.0.0.1:80");
  evio::SocketAddress sa2("127.0.0.2:80");
  evio::SocketAddressList list;
  list += sa1;
  list += sa2;
  handle->set_result(std::move(list));

  return handle;
}
