/**
 * @file
 * @brief Singleton for DNS lookups. Declaration of class DnsResolver.
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
#include "evio/InputDevice.h"
#include "farmhash/src/farmhash.h"
#include "threadpool/Timer.h"
#include "events/Events.h"
#include "threadpool/AIQueueHandle.h"
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

namespace task {
class GetAddrInfo;
class GetNameInfo;
} // namespace task

namespace resolver {

class AddressInfoHints;
class AddrInfoLookup;
class NameInfoLookup;
class DnsResolver;

// The DnsResolver must be initialized, at the start of main, after the IO event loop thread.
// A typical way that main() could start is as follows:
//
#ifdef EXAMPLE_CODE     // undefined
int main()
{
  Debug(NAMESPACE_DEBUG::init());

  AIThreadPool thread_pool;
  AIQueueHandle handler = thread_pool.new_queue(queue_capacity);

  try
  {
    // Initialize the IO event loop thread and the async hostname resolver.
    evio::EventLoop event_loop(handler);
    resolver::Scope resolver_scope(handler, recurse);   // recurse is a boolean (true or false).

...

    getaddrinfo_task = new task::GetAddrInfo(DEBUG_ONLY(true));
    getaddrinfo_task->init("www.google.com", "www");

// ... run getaddrinfo_task in an AIEngine.

    // Terminate application.
    event_loop.join();
  }
  catch (AIAlert::Error const& error)
  {
    Dout(dc::warning, error);
  }

 Dout(dc::notice, "Leaving main()...");
}
#endif // EXAMPLE_CODE
// The resolver::Scope object makes sure that the UDP socket that is used for the DNS look ups
// is cleanly closed and libdns is properly terminated upon leaving this scope.
// It must be instantiated *after* event_loop for the correct order of deinitialization
// (first the resolver teardown, then the event loop).
//
// Program flow for getaddrinfo is:
// 1) task::GetAddrInfo::init(std::string&& node, char const* service OR uint16_t port, AddressInfoHints const& hints)
//    Converts `service' to a port number if needed and then calls:
// 2) DnsResolver::queue_getaddrinfo(std::string&& node, uint16_t port, AddressInfoHints const& hints)
//    Looks up and/or stores node in m_hostname_cache. Returns handle to cache entry.
//    If a new cache entry had to be created, calls:
// 3) LibdnsWrapper::queue_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
//    If the resolver is already running, queues the new request. Otherwise calls:
// 4) LibdnsWrapper::start_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
//    Calls dns_ai_open(), sets m_dns_addrinfo and m_running, and calls run_dns().
//
// Note that the class LibdnsWrapper gives access to libdns which isn't threadsafe; therefore
// all accesses to LibdnsWrapper are protected by a mutex (through DnsResolver::m_dns_resolver).
//
// Program flow for getnameinfo is:
// 1) task::GetNameInfo::init(SocketAddress const& sock_address)
// 2) DnsResolver::queue_getnameinfo(SocketAddress const& sock_address)
// 3) LibdnsWrapper::queue_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry)
// 4) LibdnsWrapper::start_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry)
//
class DnsResolver : public Singleton<DnsResolver>
{
  //===========================================================================================================================================================
  //
  // DnsResolver is a Singleton.
  //

  friend_Instance;
 private:
  DnsResolver();
  ~DnsResolver();
  DnsResolver(DnsResolver const&) = delete;

 public:
  void init(AIQueueHandle handler, bool recurse);
  void deinit();

  //===========================================================================================================================================================
  //
  // Libdns interface.
  //

 private:
  // A socket used to connect to a DNS server (udp and/or tcp).
  class DnsSocket : public evio::InputDevice, public evio::OutputDevice
  {
   private:
    friend class DnsResolver;
    static void* dns_created_socket(int fd);
    static void dns_start_output_device(void* user_data);
    static void dns_start_input_device(void* user_data);
    static void dns_stop_output_device(void* user_data);
    static void dns_stop_input_device(void* user_data);
    static void dns_closed_fd(void* user_data);

   public:
    DnsSocket();
    ~DnsSocket();

   protected:
     void write_to_fd(int& allow_deletion_count, int fd) override;
     void read_from_fd(int& allow_deletion_count, int fd) override;
  };

  struct HostnameCacheEntry;
  struct AddressCacheEntry;

  // This is a trick; instead of wrapping the actual struct we wrap
  // the pointer to it. Of course this means we need to keep this
  // object locked while using the pointer.
  class LibdnsWrapper
  {
    struct dns_resolver* m_dns_resolver;
    struct dns_addrinfo* m_dns_addrinfo;        // Has to be protected too because it contains a pointer to dns_resolver.
    bool m_running;
    std::queue<std::pair<std::shared_ptr<HostnameCacheEntry>, AddressInfoHints>> m_getaddrinfo_queue;
    std::queue<std::shared_ptr<AddressCacheEntry>> m_getnameinfo_queue;
    std::shared_ptr<HostnameCacheEntry> m_current_addrinfo_lookup;
    std::shared_ptr<AddressCacheEntry> m_current_nameinfo_lookup;
   public:
    LibdnsWrapper() : m_dns_resolver(nullptr), m_dns_addrinfo(nullptr), m_running(false) { }
    ~LibdnsWrapper() { } // Without this I get a silly compiler warning about failing to inline the destructor.
    void set(dns_resolver* dns_resolver) { m_dns_resolver = dns_resolver; }
    struct dns_resolver* get() const { return m_dns_resolver; }
    void start_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints);
    void queue_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints);
    void start_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry);
    void queue_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry);
    void run_dns();     // Give CPU cycles to libdns.
    void close();       // Destroy m_dns_resolver and m_dns_addrinfo and reset them to nullptr.
  };

  void add(DnsSocket* dns_socket);
  void release(DnsSocket* dns_socket);

 private:
  friend class DnsSocket;       // Needs access to m_dns_resolver.
  struct dns_resolv_conf* m_dns_resolv_conf;
  using dns_resolver_ts = aithreadsafe::Wrapper<LibdnsWrapper, aithreadsafe::policy::Primitive<std::mutex>>;
  dns_resolver_ts m_dns_resolver;
  using socket_devices_ts = aithreadsafe::Wrapper<std::array<boost::intrusive_ptr<DnsSocket>, 2>, aithreadsafe::policy::Primitive<std::mutex>>;
  socket_devices_ts m_socket_devices;   // The UDP and TCP sockets.
  AIQueueHandle m_handler;

 public:
  AIQueueHandle get_handler() const { return m_handler; }

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

  using servicekey_to_port_cache_type = google::dense_hash_map<Service, uint16_t, ServiceCacheHash, ServiceCacheEqualTo>;
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
  uint16_t port(Service const& key);

  //==========================================================================
  //
  // Hostname lookup and caching interface.
  //

 private:
  // The timer used to time out queries from the DNS server.
  threadpool::Timer m_timer;

  // Timer callback functions, called from libdns. If the timer times out between a call to dns_start_timer()
  // and dns_stop_timer() then we should call dns_timed_out().
  static void dns_start_timer();
  static void dns_stop_timer();
  static void timed_out();

 public:
  struct HostnameCacheEntryReadyEvent
  {
    static constexpr bool one_shot = true;
#ifdef CWDEBUG
    friend std::ostream& operator<<(std::ostream& os, HostnameCacheEntryReadyEvent) { return os << "HostnameCacheEntryReadyEvent"; }
#endif
  };

  struct AddressCacheEntryReadyEvent
  {
    static constexpr bool one_shot = true;
#ifdef CWDEBUG
    friend std::ostream& operator<<(std::ostream& os, AddressCacheEntryReadyEvent) { return os << "AddressCacheEntryReadyEvent"; }
#endif
  };

 private:
  // This is a single entry in the m_hostname_cache.
  // These cache entries are accessed though class AddrInfoLookup.
  struct HostnameCacheEntry
  {
    std::string str;            // Node name.
    uint32_t hints;             // (Unique) hash of the hints.
    AddressInfoList result;     // The result of the query, only valid when ready is true and error is zero.
    int error;                  // If ready is true then this can be checked to see if there was an error.

    HostnameCacheEntry(std::string&& hostname, uint32_t hints) : str(std::move(hostname)), hints(hints), error(0), ready(false) { }

    bool is_ready() const { return ready.load(std::memory_order_acquire); }
    void set_ready() { ready.store(true, std::memory_order_release); m_ready_event.trigger(ready_event); }
    void set_error_empty();
    int get_error() const { return error; }
    auto& event_server() { return m_ready_event; }

   private:
    static constexpr HostnameCacheEntryReadyEvent ready_event = { };
    std::atomic_bool ready;     // Set when the query on str/hints finished.
    events::Server<HostnameCacheEntryReadyEvent> m_ready_event;   // Event server for "becoming ready", specific for this HostnameCacheEntry.
  };
  friend class AddrInfoLookup;  // Needs access to HostnameCacheEntry.

  // This is a single entry in the m_address_cache.
  // These cache entries are accessed though class NameInfoLookup.
  struct AddressCacheEntry
  {
    std::string arpa_str;       // Arpa node name of SocketAddress.
    std::string result;         // The result (canonical name) of the query, only valid when ready is true and error is zero.
    int error;                  // If ready is true then this can be checked to see if there was an error.

    AddressCacheEntry(std::string&& arpa_str) : arpa_str(std::move(arpa_str)), error(0), ready(false) { }

    bool is_ready() const { return ready.load(std::memory_order_acquire); }
    void set_ready() { ready.store(true, std::memory_order_release); m_ready_event.trigger(ready_event); }
    int get_error() const { return error; }
    auto& event_server() { return m_ready_event; }

   private:
    static constexpr AddressCacheEntryReadyEvent ready_event = { };
    std::atomic_bool ready;     // Set when the query on arpa_str finished.
    events::Server<AddressCacheEntryReadyEvent> m_ready_event;  // Event server for "becoming ready", specific for this AddressCacheEntry.
  };
  friend class NameInfoLookup;  // Needs access to AddressCacheEntry.

  struct HostnameCacheEntryHash
  {
    uint64_t operator()(std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry) const
    {
      return util::Hash64WithSeeds(hostname_cache_entry->str.data(), hostname_cache_entry->str.length(), 0x9ae16a3b2f90404fULL, hostname_cache_entry->hints);
    }
  };

  struct AddressCacheEntryHash
  {
    uint64_t operator()(std::shared_ptr<AddressCacheEntry> const& address_cache_entry) const
    {
      return util::Hash64WithSeed(address_cache_entry->arpa_str.data(), address_cache_entry->arpa_str.length(), 0x9ae16a3b2f90404fULL);
    }
  };

  struct HostnameCacheEntryEqualTo
  {
    bool operator()(std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry1, std::shared_ptr<HostnameCacheEntry> const& hostname_cache_entry2) const
    {
      return hostname_cache_entry1->hints == hostname_cache_entry2->hints && hostname_cache_entry1->str == hostname_cache_entry2->str;
    }
  };

  struct AddressCacheEntryEqualTo
  {
    bool operator()(std::shared_ptr<AddressCacheEntry> const& address_cache_entry1, std::shared_ptr<AddressCacheEntry> const& address_cache_entry2) const
    {
      return address_cache_entry1->arpa_str == address_cache_entry2->arpa_str;
    }
  };

  struct HostnameCache
  {
    utils::NodeMemoryPool memory_pool;         // Memory pool of objects stored in m_hostname_cache.
    std::unordered_set<std::shared_ptr<HostnameCacheEntry>, HostnameCacheEntryHash, HostnameCacheEntryEqualTo> unordered_set;
    HostnameCache(int nchunks) : memory_pool(nchunks) { }
  };

  struct AddressCache
  {
    utils::NodeMemoryPool memory_pool;         // Memory pool of objects stored in m_address_cache.
    std::unordered_set<std::shared_ptr<AddressCacheEntry>, AddressCacheEntryHash, AddressCacheEntryEqualTo> unordered_set;
    AddressCache(int nchunks) : memory_pool(nchunks) { }
  };

  using hostname_cache_ts = aithreadsafe::Wrapper<HostnameCache, aithreadsafe::policy::Primitive<std::mutex>>;
  hostname_cache_ts m_hostname_cache;

  using address_cache_ts = aithreadsafe::Wrapper<AddressCache, aithreadsafe::policy::Primitive<std::mutex>>;
  address_cache_ts m_address_cache;

  using getaddrinfo_memory_pool_ts = aithreadsafe::Wrapper<utils::NodeMemoryPool, aithreadsafe::policy::Primitive<std::mutex>>;
  getaddrinfo_memory_pool_ts m_getaddrinfo_memory_pool;         // Memory pool for objects returned by queue_getaddrinfo.

  using getnameinfo_memory_pool_ts = aithreadsafe::Wrapper<utils::NodeMemoryPool, aithreadsafe::policy::Primitive<std::mutex>>;
  getnameinfo_memory_pool_ts m_getnameinfo_memory_pool;         // Memory pool for objects returned by queue_getnameinfo.

  friend task::GetAddrInfo;
  std::shared_ptr<AddrInfoLookup> queue_getaddrinfo(std::string&& hostname, uint16_t port, AddressInfoHints const& hints);

 public:
  std::shared_ptr<NameInfoLookup> getnameinfo(evio::SocketAddress const& address);

  // Hostname should be std::string or char const*; the template is only to allow perfect forwarding.
  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      std::shared_ptr<AddrInfoLookup>>::type
  getaddrinfo(S1&& node, uint16_t port, AddressInfoHints const& hints = AddressInfoHints())
  {
    return queue_getaddrinfo(std::forward<std::string>(node), port, hints);
  }

  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      std::shared_ptr<AddrInfoLookup>>::type
  getaddrinfo(S1&& node, char const* service, AddressInfoHints const& hints = AddressInfoHints())
  {
    return queue_getaddrinfo(std::forward<std::string>(node), port(Service(service, hints.as_addrinfo()->ai_protocol)), hints);
  }
};

class Scope
{
 public:
  Scope(AIQueueHandle handler, bool recurse)
  {
    DnsResolver::instance().init(handler, recurse);   // recurse is a boolean (true or false).
  }

  ~Scope()
  {
    DnsResolver::instance().deinit();
  }
};

} // namespace resolver
