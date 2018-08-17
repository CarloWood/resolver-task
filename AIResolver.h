/**
 * @file
 * @brief Singleton for DNS lookups. Declaration of class AIResolver.
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

#include "AILookup.h"
#include "utils/Singleton.h"
#include "utils/NodeMemoryPool.h"
#include <boost/pool/object_pool.hpp>
#include <memory>
#include <type_traits>

class AIResolver : public Singleton<AIResolver>
{
  friend_Instance;
 private:
  AIResolver() : m_node_memory_pool(128) { }
  ~AIResolver() { }
  AIResolver(AIResolver const&) = delete;

  template<class Tp> struct Alloc;      // Forward declaration so that this struct is a friend of AIResolver.
  utils::NodeMemoryPool m_node_memory_pool;
  std::shared_ptr<AILookup> do_request(std::string&& hostname, std::string&& servicename);

 public:
  // Hostname and servicename should be std::string or char const*; the template is only to allow perfect forwarding.
  // See ai-statefultask-testsuite/src/tracked_string.cxx for the test case.
  template<typename S1, typename S2>
  typename std::enable_if<
      (std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value) &&
      (std::is_same<S2, std::string>::value || std::is_convertible<S2, std::string>::value),
      std::shared_ptr<AILookup>>::type
  request(S1&& hostname, S2&& servicename)
  {
    return do_request(std::forward<std::string>(hostname), std::forward<std::string>(servicename));
  }
};
