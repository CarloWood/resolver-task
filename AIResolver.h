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
#include "evio/Device.h"
#include "evio/AddressInfo.h"
#include <boost/intrusive_ptr.hpp>
#include <memory>
#include <array>
#include <type_traits>

namespace evio {
class AddressInfoHints;
} // namespace evio;

struct dns_resolv_conf;
struct dns_resolver;
struct dns_addrinfo;

class AIResolver : public Singleton<AIResolver>
{
  friend_Instance;
 private:
  AIResolver() : m_dns_resolv_conf(nullptr), m_dns_resolver(nullptr), m_node_memory_pool(128) { }
  ~AIResolver();
  AIResolver(AIResolver const&) = delete;

  template<class Tp> struct Alloc;      // Forward declaration so that this struct is a friend of AIResolver.

  class ResolverDevice : public evio::InputDevice, public evio::OutputDevice
  {
   private:
    friend AIResolver;
    static void* dns_created_socket(int fd);
    static void dns_wants_to_write(void* user_data);
    static void dns_wants_to_read(void* user_data);
    static void dns_closed_fd(void* user_data);

   public:
    ResolverDevice();
    ~ResolverDevice();

   protected:
    void write_to_fd(int fd) override;    // Write thread.
    void read_from_fd(int fd) override;   // Read thread.
    RefCountReleaser closed() override;
  };

  struct dns_resolv_conf* m_dns_resolv_conf;
  struct dns_resolver* m_dns_resolver;
  struct dns_addrinfo* m_dns_addrinfo;
  std::array<boost::intrusive_ptr<ResolverDevice>, 2> m_resolver_devices;
  utils::NodeMemoryPool m_node_memory_pool;
  evio::AddressInfoList m_addrinfo;
  std::shared_ptr<AILookup> m_lookup;

  std::shared_ptr<AILookup> queue_request(std::string&& hostname, std::string&& servicename, evio::AddressInfoHints const& hints);
  void run_dns();

 public:
  void init(bool recurse);

  // Hostname and servicename should be std::string or char const*; the template is only to allow perfect forwarding.
  // See ai-statefultask-testsuite/src/tracked_string.cxx for the test case.
  template<typename S1, typename S2>
  typename std::enable_if<
      (std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value) &&
      (std::is_same<S2, std::string>::value || std::is_convertible<S2, std::string>::value),
      std::shared_ptr<AILookup>>::type
  getaddrinfo(S1&& node, S2&& service, evio::AddressInfoHints const& hints = evio::AddressInfoHints())
  {
    return queue_request(std::forward<std::string>(node), std::forward<std::string>(service), hints);
  }

  void close()
  {
    DoutEntering(dc::notice, "AIResolver::close()");
    for (unsigned int d = 0; d < m_resolver_devices.size(); ++d)
    {
      if (m_resolver_devices[d])
      {
        m_resolver_devices[d]->close_input_device();
        m_resolver_devices[d].reset();
      }
    }
  }
};
