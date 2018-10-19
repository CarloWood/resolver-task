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

#include "Service.h"
#include "AddressInfo.h"
#include "utils/Singleton.h"
#include "utils/NodeMemoryPool.h"
#include "evio/Device.h"
#include "farmhash/src/farmhash.h"
#include "statefultask/Timer.h"
#include "events/Events.h"
#include <boost/intrusive_ptr.hpp>
#include <sparsehash/dense_hash_map>
#include <memory>
#include <array>
#include <unordered_set>
#include <type_traits>
#include <atomic>
#include <queue>

struct dns_resolv_conf;
struct dns_resolver;
struct dns_addrinfo;
class AILookupTask;

namespace resolver {

class AddressInfoHints;
class Lookup;

// The Resolver must be initialized, at the start of main, after the IO event loop thread.
// A typical way that main() could start is as follows:
//
// using resolver::Resolver;
//
// int main()
// {
//   Debug(NAMESPACE_DEBUG::init());
//
//   AIThreadPool thread_pool;
//   AIQueueHandle handler = thread_pool.new_queue(queue_capacity);
//   // Initialize the IO event loop thread.
//   EventLoopThread::instance().init(handler);
//   // Initialize the async hostname resolver.
//   Resolver::instance().init(recurse);        // recurse is a boolean (true or false).
//
//...
//
//   // Terminate application.
//   Resolver::instance().close();
//   EventLoopThread::instance().terminate();
// }
class Resolver : public Singleton<Resolver>
{
  //===========================================================================================================================================================
  //
  // Resolver is a Singleton.
  //

  friend_Instance;
 private:
  Resolver();
  ~Resolver();
  Resolver(Resolver const&) = delete;

 public:
  void init(bool recurse);

  //===========================================================================================================================================================
  //
  // Libdns interface.
  //

 private:
  // A socket used to connect to a DNS server (udp and/or tcp).
  class SocketDevice : public evio::InputDevice, public evio::OutputDevice
  {
   private:
    friend Resolver;
    static void* dns_created_socket(int fd);
    static void dns_start_output_device(void* user_data);
    static void dns_start_input_device(void* user_data);
    static void dns_stop_output_device(void* user_data);
    static void dns_stop_input_device(void* user_data);
    static void dns_closed_fd(void* user_data);

   public:
    SocketDevice();
    ~SocketDevice();

   protected:
    void write_to_fd(int fd) override;    // Write thread.
    void read_from_fd(int fd) override;   // Read thread.
  };

  struct HostnameCacheEntry;

  // This is a trick; instead of wrapping the actual struct we wrap
  // the pointer to it. Of course this means we need to keep this
  // object locked while using the pointer.
  class DnsResolver
  {
    struct dns_resolver* m_dns_resolver;
    struct dns_addrinfo* m_dns_addrinfo;        // Has to be protected too because it contains a pointer to dns_resolver.
    std::queue<std::pair<std::shared_ptr<HostnameCacheEntry>, AddressInfoHints>> m_request_queue;
    std::shared_ptr<HostnameCacheEntry> m_current_lookup;
   public:
    DnsResolver() : m_dns_resolver(nullptr), m_dns_addrinfo(nullptr) { }
    ~DnsResolver() noexcept { } // Without this I get a silly compiler warning about failing to inline the destructor.
    void set(dns_resolver* dns_resolver) { m_dns_resolver = dns_resolver; }
    struct dns_resolver* get() const { return m_dns_resolver; }
    void start_lookup(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints);
    void queue_request(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints);
    void run_dns();     // Give CPU cycles to libdns.
  };

  struct dns_resolv_conf* m_dns_resolv_conf;
  using dns_resolver_ts = aithreadsafe::Wrapper<DnsResolver, aithreadsafe::policy::Primitive<std::mutex>>;
  dns_resolver_ts m_dns_resolver;

  using socket_devices_ts = aithreadsafe::Wrapper<std::array<boost::intrusive_ptr<SocketDevice>, 2>, aithreadsafe::policy::Primitive<std::mutex>>;
  socket_devices_ts m_socket_devices;   // The UDP and TCP sockets.

 public:
  void close();

  //===========================================================================================================================================================
  //
  // Service lookup and caching interface.
  //

  struct ServiceCacheHash
  {
    uint64_t operator()(Service const& key) const
    {
      return key.hash();
    }
  };

  struct ServiceCacheEqualTo
  {
    bool operator()(Service const& key1, Service const& key2) const
    {
      return key1.protocol() == key2.protocol() && std::strcmp(key1.name(), key2.name()) == 0;
    }
  };

  using servicekey_to_port_cache_type = google::dense_hash_map<Service, in_port_t, ServiceCacheHash, ServiceCacheEqualTo>;
  using servicekey_to_port_cache_ts = aithreadsafe::Wrapper<servicekey_to_port_cache_type, aithreadsafe::policy::Primitive<std::mutex>>;

  servicekey_to_port_cache_ts m_servicekey_to_port_cache;               // Cache for storing service/protocol to port number map.

 public:
  // Return the cannonical string that is used in /etc/protocols for this protocol.
  // This function is cached and thread-safe.
  static char const* protocol_str(in_proto_t protocol);

  // Convert a protocol string to a protocol number (thread-safe).
  static in_proto_t protocol(char const* protocol_str);

  // Return the port number corresponding to the service name / protocol combination `key'.
  // This function is cached and thread-safe.
  in_port_t port(Service const& key);

  //==========================================================================
  //
  // Hostname lookup and caching interface.
  //

 private:
  // The timer used to time out queries from the DNS server.
  statefultask::Timer m_timer;

  // Timer callback functions, called from libdns. If the timer times out between a call to dns_start_timer()
  // and dns_stop_timer() then we should call dns_timed_out().
  static void dns_start_timer();
  static void dns_stop_timer();
  static void timed_out();

  struct HostnameCacheEntryReadyEvent
  {
    static constexpr bool one_shot = true;
#ifdef CWDEBUG
    friend std::ostream& operator<<(std::ostream& os, HostnameCacheEntryReadyEvent) { return os << "HostnameCacheEntryReadyEvent"; }
#endif
  };

  // This is a single entry in the m_hostname_cache.
  // These cache entries are accessed though class Lookup.
  struct HostnameCacheEntry
  {
    std::string str;            // Node name.
    uint32_t hints;             // (Unique) hash of the hints.
    AddressInfoList result;     // The result of the query, only valid when ready is true and error is zero.
    int error;                  // If ready is true then this can be checked to see if there was an error.

    HostnameCacheEntry(std::string&& hostname, uint32_t hints) : str(std::move(hostname)), hints(hints), error(0), ready(false) { }

    bool is_ready() const { return ready.load(std::memory_order_acquire); }
    void set_ready() { ready.store(true, std::memory_order_release); m_ready_event.trigger(ready_event); }
    int get_error() const { return error; }
    auto& event_server() { return m_ready_event; }

   private:
    static constexpr HostnameCacheEntryReadyEvent ready_event = { };
    std::atomic_bool ready;     // Set when the query on str/hints finished.
    events::Server<HostnameCacheEntryReadyEvent> m_ready_event;   // Event server for "becoming ready", specific for this HostnameCacheEntry.
  };
  friend class Lookup;  // Needs access to HostnameCacheEntry.

  struct HostnameCacheEntryHash
  {
    uint64_t operator()(std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry) const
    {
      return util::Hash64WithSeeds(hostname_cache_entry->str.data(), hostname_cache_entry->str.length(), 0x9ae16a3b2f90404fULL, hostname_cache_entry->hints);
    }
  };

  struct HostnameCacheEntryEqualTo
  {
    bool operator()(std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry1, std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry2) const
    {
      return hostname_cache_entry1->hints == hostname_cache_entry2->hints && hostname_cache_entry1->str == hostname_cache_entry2->str;
    }
  };

  struct HostnameCache
  {
    utils::NodeMemoryPool memory_pool;         // Memory pool of objects stored in m_hostname_cache.
    std::unordered_set<std::shared_ptr<HostnameCacheEntry>, HostnameCacheEntryHash, HostnameCacheEntryEqualTo> unordered_set;
    HostnameCache(int nchunks) : memory_pool(nchunks) { }
  };

  using hostname_cache_ts = aithreadsafe::Wrapper<HostnameCache, aithreadsafe::policy::Primitive<std::mutex>>;
  hostname_cache_ts m_hostname_cache;

  using lookup_memory_pool_ts = aithreadsafe::Wrapper<utils::NodeMemoryPool, aithreadsafe::policy::Primitive<std::mutex>>;
  lookup_memory_pool_ts m_lookup_memory_pool;                   // Memory pool for objects returned by queue_request.

  friend AILookupTask;
  std::shared_ptr<Lookup> queue_request(std::string&& hostname, in_port_t port, AddressInfoHints const& hints);

 public:
  // Hostname should be std::string or char const*; the template is only to allow perfect forwarding.
  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      std::shared_ptr<Lookup>>::type
  getaddrinfo(S1&& node, in_port_t port, AddressInfoHints const& hints = AddressInfoHints())
  {
    return queue_request(std::forward<std::string>(node), port, hints);
  }

  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      std::shared_ptr<Lookup>>::type
  getaddrinfo(S1&& node, char const* service, AddressInfoHints const& hints = AddressInfoHints())
  {
    return queue_request(std::forward<std::string>(node), port(Service(service, hints.as_addrinfo()->ai_protocol)), hints);
  }
};

} // namespace resolver
