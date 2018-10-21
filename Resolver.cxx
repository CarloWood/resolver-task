/**
 * @file
 * @brief Implementation of Resolver.
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
#include "Lookup.h"
#include "dns/src/dns.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"
#include "utils/AIAlert.h"
#include <arpa/inet.h>
#include <cstring>

namespace resolver {

unsigned int const buffer_max_packet_size = (dns_p_calcsize(512) + 63) & 63;    // Round up to multiple of 64 (640 bytes) for no reason.

Resolver::SocketDevice::SocketDevice() :
  evio::InputDevice(nullptr), evio::OutputDevice(nullptr)       // SocketDevice doesn't use (our) buffers.
{
  DoutEntering(dc::notice, "Resolver::SocketDevice::SocketDevice()");
}

Resolver::SocketDevice::~SocketDevice()
{
  DoutEntering(dc::notice, "Resolver::SocketDevice::~SocketDevice()");
}

//static
void* Resolver::SocketDevice::dns_created_socket(int fd)
{
  DoutEntering(dc::notice, "SocketDevice::dns_created_socket(" << fd << ")");
  SocketDevice* resolver_device = new SocketDevice();
  resolver_device->init(fd);
  resolver_device->m_flags |= INTERNAL_FDS_DONT_CLOSE; // Let the closing be done by libdns.
  // Increment ref count to stop this SocketDevice from being deleted while being used by libdns.
  socket_devices_ts::wat socket_devices_w(Resolver::instance().m_socket_devices);
  for (unsigned int d = 0; d < socket_devices_w->size(); ++d)
  {
    boost::intrusive_ptr<SocketDevice>& device_ptr(socket_devices_w->operator[](d));
    if (!device_ptr)
    {
      device_ptr = resolver_device;
      return resolver_device;
    }
  }
  DoutFatal(dc::core, "Resolver::SocketDevice::dns_created_socket: creating more than 2 sockets?!");
}

void Resolver::close()
{
  DoutEntering(dc::notice, "Resolver::close()");
  socket_devices_ts::wat socket_devices_w(m_socket_devices);
  for (unsigned int d = 0; d < socket_devices_w->size(); ++d)
  {
    boost::intrusive_ptr<SocketDevice>& device_ptr(socket_devices_w->operator[](d));
    if (device_ptr)
    {
      device_ptr->close_input_device();
      device_ptr.reset();
    }
  }
}

//static
void Resolver::SocketDevice::dns_start_output_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_start_output_device()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->start_output_device();
}

//static
void Resolver::SocketDevice::dns_start_input_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_start_input_device()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->start_input_device();
}

//static
void Resolver::SocketDevice::dns_stop_output_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_stop_output_device()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->stop_output_device();
}

//static
void Resolver::SocketDevice::dns_stop_input_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_stop_input_device()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->stop_input_device();
}

//static
void Resolver::SocketDevice::dns_closed_fd(void* user_data)
{
  DoutEntering(dc::notice, "dns_closed_fd()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  RefCountReleaser releaser;
  // Decrement ref count again (after incrementing it in dns_created_socket) now that libdns is done with it.
  releaser = self;
  releaser += self->close_input_device();
  releaser += self->close_output_device();
  ASSERT(self->is_dead());
}

void Resolver::SocketDevice::write_to_fd(int DEBUG_ONLY(fd))
{
  DoutEntering(dc::evio, "Resolver::SocketDevice::write_to_fd(" << fd << ")");
  dns_resolver_ts::wat dns_resolver_w(Resolver::instance().m_dns_resolver);
  dns_so_is_writable(dns_resolver_w->get(), this);
  dns_resolver_w->run_dns();
}

void Resolver::SocketDevice::read_from_fd(int DEBUG_ONLY(fd))
{
  DoutEntering(dc::evio, "Resolver::SocketDevice::read_from_fd(" << fd << ")");
  dns_resolver_ts::wat dns_resolver_w(Resolver::instance().m_dns_resolver);
  dns_so_is_readable(dns_resolver_w->get(), this);
  dns_resolver_w->run_dns();
}

void Resolver::init(bool recurse)
{
  // Initialize dns.
  static struct dns_options const opts = { { nullptr, nullptr }, dns_options::DNS_LIBEVENT };
  int error = 0;
  char const* error_function = nullptr;
  struct dns_hosts* hosts = nullptr;
  struct dns_hints* hints = nullptr;

  dns_resolver_ts::wat dns_resolver_w(Resolver::instance().m_dns_resolver);

  do    // So we can use break (error).
  {
    if (recurse)
    {
      if (!(m_dns_resolv_conf = dns_resconf_root(&error)))
        { error_function = "dns_resconf_root"; break; }

      if (!(hosts = dns_hosts_local(&error)))
        { error_function = "dns_hosts_local"; break; }

      if (!(hints = dns_hints_root(m_dns_resolv_conf, &error)))
        { error_function = "dns_hints_root"; break; }
    }
    else
    {
      if (!(m_dns_resolv_conf = dns_resconf_local(&error)))
        { error_function = "dns_resconf_local"; break; }

      if (!(hosts = dns_hosts_local(&error)))
        { error_function = "dns_hosts_local"; break; }

      if (!(hints = dns_hints_local(m_dns_resolv_conf, &error)))
        { error_function = "dns_hints_local"; break; }
    }

    struct dns_resolver* resolver = dns_res_open(m_dns_resolv_conf, hosts, hints, nullptr, &opts, &error);
    if (!resolver)
      { error_function = "dns_res_open"; break; }

    // Set callback functions; this calls dns_created_socket for the already created UDP socket before it returns.
    dns_set_so_hooks(resolver,
        &SocketDevice::dns_created_socket,
        &SocketDevice::dns_start_output_device,
        &SocketDevice::dns_start_input_device,
        &SocketDevice::dns_stop_output_device,
        &SocketDevice::dns_stop_input_device,
        &Resolver::dns_start_timer,
        &Resolver::dns_stop_timer,
        &SocketDevice::dns_closed_fd);
    // Store the resolver pointer with mutex protection.
    dns_resolver_w->set(resolver);
  }
  while (0);
  if (error_function)
  {
    // It is OK to call these three with a nullptr.
    dns_hints_close(hints);
    dns_hosts_close(hosts);
    dns_resconf_close(m_dns_resolv_conf);
    THROW_MALERT("[ERROR_FUNCTION]() returned \"[ERROR_MSG]\".", AIArgs("[ERROR_FUNCTION]", error_function)("[ERROR_MSG]", dns_strerror(error)));
  }
}

Resolver::Resolver() : m_dns_resolv_conf(nullptr), m_timer(&timed_out), m_hostname_cache(128), m_lookup_memory_pool(32)
{
  Service const impossible_key("..", 244);      // Protocol 244 doesn't exist, nor does a service named "..".
  servicekey_to_port_cache_ts::wat(m_servicekey_to_port_cache)->set_empty_key(impossible_key);
}

Resolver::~Resolver()
{
  // It is OK to call this with a nullptr.
  dns_res_close(dns_resolver_ts::wat(m_dns_resolver)->get());
}

//static
void Resolver::dns_start_timer()
{
  DoutEntering(dc::notice, "Resolver::dns_start_timer()");
  instance().m_timer.start(statefultask::Interval<1, std::chrono::seconds>());
}

//static
void Resolver::dns_stop_timer()
{
  DoutEntering(dc::notice, "Resolver::dns_stop_timer()");
  instance().m_timer.stop();
}

//static
void Resolver::timed_out()
{
  DoutEntering(dc::notice, "Resolver::timed_out()");
  dns_resolver_ts::wat dns_resolver_w(instance().m_dns_resolver);
  dns_timed_out(dns_resolver_w->get());
  dns_resolver_w->run_dns();
}

void Resolver::DnsResolver::run_dns()
{
  int error;
  for (;;)
  {
    struct addrinfo* addrinfo;

    // Give CPU to libdns until it returns a non-zero value.
    if ((error = dns_ai_nextent(&addrinfo, m_dns_addrinfo)))
      break;

    m_current_lookup->result.add(addrinfo);
  }

  if (error == EAGAIN)
    return;

  if (error != ENOENT)
    m_current_lookup->error = error;

  Dout(dc::notice, "Calling set_ready()");
  m_current_lookup->set_ready();

  // At this point the DnsResolver is no longer busy, provided this
  // is only checked while holding a lock on Resolver::m_dns_resolver.
  m_dns_addrinfo = nullptr;

  if (!m_getaddrinfo_queue.empty())
  {
    auto& next_request = m_getaddrinfo_queue.front();
    start_lookup(next_request.first, next_request.second);
    m_getaddrinfo_queue.pop();
  }
}

void Resolver::DnsResolver::start_lookup(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
{
  m_current_lookup = new_cache_entry;
  // Call Resolver.instance().init() at the start of main() to initialize the resolver.
  ASSERT(m_dns_resolver);
  int error = 0;        // Must be set to 0.
  struct dns_addrinfo* addrinfo = dns_ai_open(m_current_lookup->str.c_str(), nullptr, (dns_type)0, hints.as_addrinfo(), m_dns_resolver, &error);
  if (!addrinfo)
  {
    std::ostringstream hints_ss;
    hints_ss << hints;
    THROW_MALERT("dns_ai_open(\"[HOSTNAME]\") [with hints '[HINTS]'] returned \"[ERROR_MSG]\".",
        AIArgs("[HOSTNAME]", m_current_lookup->str.c_str())("[HINTS]", hints_ss.str())("[ERROR_MSG]", dns_strerror(error)));
  }
  // A previous request should already have been moved to its corresponding Lookup object in run_dns(), before we get here again.
  ASSERT(m_current_lookup->result.empty());
  m_dns_addrinfo = addrinfo;
  run_dns();
}

void Resolver::DnsResolver::queue_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
{
  // Check if the dns lib is busy with another lookup (yeah, it doesn't support doing lookups in parallel).
  if (m_dns_addrinfo)
    m_getaddrinfo_queue.emplace(new_cache_entry, hints);
  else
    start_lookup(new_cache_entry, hints);
}

std::shared_ptr<Lookup> Resolver::queue_getaddrinfo(std::string&& hostname, in_port_t port, AddressInfoHints const& hints)
{
  DoutEntering(dc::notice, "Resolver::queue_getaddrinfo(\"" << hostname << "\", " << port << ", " << hints << ")");

  bool new_cache_entry;
  std::shared_ptr<HostnameCacheEntry> const* new_cache_entry_ptr;
  {
    hostname_cache_ts::wat hostname_cache_w(m_hostname_cache);
    utils::Allocator<HostnameCacheEntry, utils::NodeMemoryPool> hostname_cache_allocator(hostname_cache_w->memory_pool);
    auto insert_result = hostname_cache_w->unordered_set.insert(std::allocate_shared<HostnameCacheEntry>(hostname_cache_allocator, std::move(hostname), hints.hash_seed()));
    new_cache_entry_ptr = &*insert_result.first;
    new_cache_entry = insert_result.second;
  }
  Dout(dc::notice, (new_cache_entry ? "Insert into hostname cache took place." : "Found cached entry!"));

  // If this was a new Lookup, query the DNS server(s).
  if (new_cache_entry)
    dns_resolver_ts::wat(m_dns_resolver)->queue_getaddrinfo(*new_cache_entry_ptr, hints);

  return std::allocate_shared<Lookup>(utils::Allocator<Lookup, utils::NodeMemoryPool>(*lookup_memory_pool_ts::wat(m_lookup_memory_pool)), *new_cache_entry_ptr, port);
}

// Return the official protocol name of `protocol'.
// If protocol == 0, returns nullptr; otherwise if protocol doesn't exist, returns "unknown".
//static
char const* Resolver::protocol_str(in_proto_t protocol)
{
  // A simple map from protocol numbers to protocol strings.
  using protocol_names_type = aithreadsafe::Wrapper<std::array<char const*, IPPROTO_MAX>, aithreadsafe::policy::Primitive<std::mutex>>;
  static protocol_names_type protocol_names_s;

  char const* name = protocol_names_type::rat(protocol_names_s)->operator[](protocol);
  if (AI_LIKELY(name || protocol == 0))
    return name;

  struct protoent result_buf;
  char buf[1024];
  size_t buflen = sizeof(buf);
  char* bufptr = buf;
  struct protoent* result;
  int error;
  for (;;)
  {
    error = getprotobynumber_r(protocol, &result_buf, bufptr, buflen, &result);
    if (AI_LIKELY(error != ERANGE))
      break;
    if (bufptr == buf)
      bufptr = nullptr;
    buflen += 1024;
    bufptr = (char*)std::realloc(bufptr, buflen);
  }
  // Is there any other error possible than ERANGE?
  ASSERT(error == 0);
  if (AI_LIKELY(result))
  {
    name = strdup(result->p_name);
    ASSERT(result->p_proto == protocol);
  }
  else
  {
    Dout(dc::warning, "Unknown protocol number " << static_cast<int>(protocol) << "!");
    name = "unknown";
  }

  {
    protocol_names_type::rat protocol_names_w(protocol_names_s);
    if (AI_UNLIKELY(protocol_names_w->operator[](protocol)))        // Make sure another thread didn't already initialize this entry in the meantime.
    {
      if (result)
        std::free(const_cast<char*>(name));
      name = protocol_names_w->operator[](protocol);
    }
    else
      protocol_names_w->operator[](protocol) = name;
  }

  if (AI_UNLIKELY(buflen > sizeof(buf)))
    std::free(bufptr);

  return name;
}

// Return protocol number of `protocol_str'.
// If protocol_str is nullptr then returns 0.
//static
in_proto_t Resolver::protocol(char const* protocol_str)
{
  // Let nullptr mean 'any protocol'.
  if (protocol_str == nullptr)
    return 0;

  // Speed up for the strings "tcp" and "udp", where
  // we assume that protocol_str is a valid protocol name.
  // There are no protocol names of less than 2 characters, so protocol_str[2] always exists.
  // Once the third character is a 'p' then the fourth character also always exists.
  if (protocol_str[2] == 'p' && protocol_str[3] == '\0')
  {
    if (protocol_str[0] == 't' && protocol_str[1] == 'c')
      return IPPROTO_TCP;
    if (protocol_str[0] == 'u' && protocol_str[1] == 'd')
      return IPPROTO_UDP;
  }

  struct protoent result_buf;
  char buf[1024];
  size_t buflen = sizeof(buf);
  char* bufptr = buf;
  struct protoent* result;
  int error;
  for (;;)
  {
    error = getprotobyname_r(protocol_str, &result_buf, bufptr, buflen, &result);
    if (AI_LIKELY(error != ERANGE))
      break;
    if (bufptr == buf)
      bufptr = nullptr;
    buflen += 1024;
    bufptr = (char*)std::realloc(bufptr, buflen);
  }
  // Is there any other error possible than ERANGE?
  ASSERT(error == 0);
  in_proto_t protocol;
  if (AI_LIKELY(result))
    protocol = result->p_proto;
  else
  {
    Dout(dc::warning, "Unknown protocol string \"" << protocol_str << "\"!");
    protocol = 0;
  }
  if (AI_UNLIKELY(buflen > sizeof(buf)))
    std::free(bufptr);
  return protocol;
}

in_port_t Resolver::port(Service const& key)
{
  in_port_t port;
  bool found;
  {
    servicekey_to_port_cache_ts::rat servicekey_to_port_cache_r(m_servicekey_to_port_cache);
    auto iter = servicekey_to_port_cache_r->find(key);
    found = iter != servicekey_to_port_cache_r->end();
    if (AI_LIKELY(found))
      port = iter->second;
  }
  if (AI_UNLIKELY(!found))
  {
    struct servent result_buf;
    char buf[1024];
    size_t buflen = sizeof(buf);
    char* bufptr = buf;
    struct servent* result;
    int error;
    for (;;)
    {
      error = getservbyname_r(key.name(), protocol_str(key.protocol()), &result_buf, bufptr, buflen, &result);
      if (AI_LIKELY(error != ERANGE))
        break;
      if (bufptr == buf)
        bufptr = nullptr;
      buflen += 1024;
      bufptr = (char*)std::realloc(bufptr, buflen);
    }
    // Is there any other error possible than ERANGE?
    ASSERT(error == 0);
    if (AI_LIKELY(result))
      port = ntohs(result->s_port);
    else
    {
#ifdef CWDEBUG
      char const* ps = protocol_str(key.protocol());
      Dout(dc::warning, "Unknown service string \"" << key.name() << "\" for protocol \"" << (ps ? ps : "<any>") << "\"!");
#endif
      port = 0;
    }
    if (AI_UNLIKELY(buflen > sizeof(buf)))
      std::free(bufptr);
    servicekey_to_port_cache_ts::wat servicekey_to_port_cache_w(m_servicekey_to_port_cache);
    servicekey_to_port_cache_w->operator[](key) = port;
  }
  return port;
}

} // namespace resolver

namespace {
SingletonInstance<resolver::Resolver> dummy __attribute__ ((__unused__));
} // namespace
