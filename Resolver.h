/**
 * @file
 * @brief Singleton for DNS lookups. Declaration of class Resolver.
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

#include "Lookup.h"
#include "utils/Singleton.h"
#include "utils/NodeMemoryPool.h"
#include "evio/Device.h"
#include "farmhash/src/farmhash.h"
#include <boost/intrusive_ptr.hpp>
#include <memory>
#include <array>
#include <unordered_set>
#include <type_traits>

struct dns_resolv_conf;
struct dns_resolver;
struct dns_addrinfo;

namespace resolver {

class AddressInfoHints;

class Resolver : public Singleton<Resolver>
{
  friend_Instance;
 private:
  Resolver() : m_dns_resolv_conf(nullptr), m_dns_resolver(nullptr), m_node_memory_pool(128) { }
  ~Resolver();
  Resolver(Resolver const&) = delete;

  template<class Tp> struct Alloc;      // Forward declaration so that this struct is a friend of Resolver.

  class SocketDevice : public evio::InputDevice, public evio::OutputDevice
  {
   private:
    friend Resolver;
    static void* dns_created_socket(int fd);
    static void dns_wants_to_write(void* user_data);
    static void dns_wants_to_read(void* user_data);
    static void dns_closed_fd(void* user_data);

   public:
    SocketDevice();
    ~SocketDevice();

   protected:
    void write_to_fd(int fd) override;    // Write thread.
    void read_from_fd(int fd) override;   // Read thread.
  };

  struct CacheHash
  {
    uint64_t operator()(std::shared_ptr<Lookup> const& lookup) const
    {
      return util::Hash64WithSeeds(lookup->get_hostname().data(), lookup->get_hostname().length(), lookup->get_service().hash_seed(), lookup->get_hints());
    }
  };

  struct CacheEqualTo
  {
    bool operator()(std::shared_ptr<Lookup> const& lookup1, std::shared_ptr<Lookup> const& lookup2) const;
  };

  struct dns_resolv_conf* m_dns_resolv_conf;
  struct dns_resolver* m_dns_resolver;
  struct dns_addrinfo* m_dns_addrinfo;
  std::array<boost::intrusive_ptr<SocketDevice>, 2> m_socket_devices;
  utils::NodeMemoryPool m_node_memory_pool;
  AddressInfoList m_addrinfo;
  std::shared_ptr<Lookup> m_lookup;
  std::unordered_set<std::shared_ptr<Lookup>, CacheHash, CacheEqualTo> m_cache;

  std::shared_ptr<Lookup> queue_request(std::string&& hostname, Service const& service, AddressInfoHints const& hints);
  void run_dns();

 public:
  void init(bool recurse);

  // Hostname should be std::string or char const*; the template is only to allow perfect forwarding.
  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      std::shared_ptr<Lookup>>::type
  getaddrinfo(S1&& node, Service const& service, AddressInfoHints const& hints = AddressInfoHints())
  {
    return queue_request(std::forward<std::string>(node), service, hints);
  }

  void close()
  {
    DoutEntering(dc::notice, "Resolver::close()");
    for (unsigned int d = 0; d < m_socket_devices.size(); ++d)
    {
      if (m_socket_devices[d])
      {
        m_socket_devices[d]->close_input_device();
        m_socket_devices[d].reset();
      }
    }
  }
};

} // namespace resolver
