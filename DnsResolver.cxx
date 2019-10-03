/**
 * @file
 * @brief Implementation of DnsResolver.
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
#include "NameInfoLookup.h"
#include "dns/src/dns.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"
#include "utils/AIAlert.h"
#include "evio/StreamBuf-threads.h"
#include <arpa/inet.h>
#include <cstring>

namespace resolver {

unsigned int const buffer_max_packet_size = (dns_p_calcsize(512) + 63) & 63;    // Round up to multiple of 64 (640 bytes) for no reason.

DnsResolver::DnsSocket::DnsSocket()
{
  DoutEntering(dc::notice, "DnsSocket::DnsSocket()");
}

DnsResolver::DnsSocket::~DnsSocket()
{
  DoutEntering(dc::notice, "DnsSocket::~DnsSocket()");
}

//static
void* DnsResolver::DnsSocket::dns_created_socket(int fd)
{
  DoutEntering(dc::notice, "DnsSocket::dns_created_socket(" << fd << ")");
  DnsSocket* resolver_device = new DnsSocket();
  resolver_device->init(fd);
  state_t::wat(resolver_device->m_state)->m_flags.set_dont_close(); // Let the closing be done by libdns.
  DnsResolver::instance().add(resolver_device);
  return resolver_device;
}

void DnsResolver::add(DnsSocket* dns_socket)
{
  // Increment ref count to stop this DnsSocket from being deleted while being used by libdns.
  socket_devices_ts::wat socket_devices_w(m_socket_devices);
  for (unsigned int d = 0; d < socket_devices_w->size(); ++d)
  {
    boost::intrusive_ptr<DnsSocket>& device_ptr(socket_devices_w->operator[](d));
    if (!device_ptr)
    {
      device_ptr = dns_socket;
      return;
    }
  }
  DoutFatal(dc::core, "DnsSocket::dns_created_socket: creating more than 2 sockets?!");
}

void DnsResolver::release(DnsSocket* dns_socket)
{
  DoutEntering(dc::notice, "DnsResolver::release(" << dns_socket << ")");
  DnsResolver::socket_devices_ts::wat socket_devices_w(m_socket_devices);
  for (unsigned int d = 0; d < socket_devices_w->size(); ++d)
  {
    boost::intrusive_ptr<DnsSocket>& device_ptr(socket_devices_w->operator[](d));
    if (device_ptr.get() == dns_socket)
      device_ptr.reset();
  }
}

//static
void DnsResolver::DnsSocket::dns_start_output_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_start_output_device()");
  DnsSocket* self = static_cast<DnsSocket*>(user_data);
  self->start_output_device();
}

//static
void DnsResolver::DnsSocket::dns_start_input_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_start_input_device()");
  DnsSocket* self = static_cast<DnsSocket*>(user_data);
  self->start_input_device();
}

//static
void DnsResolver::DnsSocket::dns_stop_output_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_stop_output_device()");
  DnsSocket* self = static_cast<DnsSocket*>(user_data);
  self->stop_output_device();
}

//static
void DnsResolver::DnsSocket::dns_stop_input_device(void* user_data)
{
  DoutEntering(dc::notice, "dns_stop_input_device()");
  DnsSocket* self = static_cast<DnsSocket*>(user_data);
  self->stop_input_device();
}

//static
void DnsResolver::DnsSocket::dns_closed_fd(void* user_data)
{
  DnsSocket* self = static_cast<DnsSocket*>(user_data);
  DoutEntering(dc::notice, "dns_closed_fd(" << self << ")");
  // Decrement ref count again (after incrementing it in dns_created_socket) now that libdns is done with it.
  DnsResolver::instance().release(self);
}

void DnsResolver::DnsSocket::write_to_fd(int& CWDEBUG_ONLY(allow_deletion_count), int CWDEBUG_ONLY(fd))
{
  DoutEntering(dc::io, "DnsSocket::write_to_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
  DnsResolver::dns_resolver_ts::wat dns_resolver_w(DnsResolver::instance().m_dns_resolver);
  dns_so_is_writable(dns_resolver_w->get(), this);
  dns_resolver_w->run_dns();
}

void DnsResolver::DnsSocket::read_from_fd(int& CWDEBUG_ONLY(allow_deletion_count), int CWDEBUG_ONLY(fd))
{
  DoutEntering(dc::io, "DnsSocket::read_from_fd({" << allow_deletion_count << "}, " << fd << ") [" << this << ']');
  DnsResolver::dns_resolver_ts::wat dns_resolver_w(DnsResolver::instance().m_dns_resolver);
  dns_so_is_readable(dns_resolver_w->get(), this);
  dns_resolver_w->run_dns();
}

void DnsResolver::init(AIQueueHandle handler, bool recurse)
{
  DoutEntering(dc::notice, "DnsResolver::init(" << handler << ", " << recurse << ")");

  // Just remember some non-immediate handler for use by GetAddrInfo and GetNameInfo tasks.
  m_handler = handler;

  // Initialize dns.
  static struct dns_options const opts = { { nullptr, nullptr }, dns_options::DNS_LIBEVENT };
  int error = 0;
  char const* error_function = nullptr;
  struct dns_hosts* hosts = nullptr;
  struct dns_hints* hints = nullptr;

  dns_resolver_ts::wat dns_resolver_w(DnsResolver::instance().m_dns_resolver);

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
        &DnsSocket::dns_created_socket,
        &DnsSocket::dns_start_output_device,
        &DnsSocket::dns_start_input_device,
        &DnsSocket::dns_stop_output_device,
        &DnsSocket::dns_stop_input_device,
        &DnsResolver::dns_start_timer,
        &DnsResolver::dns_stop_timer,
        &DnsSocket::dns_closed_fd);
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

void DnsResolver::deinit()
{
  DoutEntering(dc::notice, "DnsResolver::deinit()");
  {
    DnsResolver::socket_devices_ts::wat socket_devices_w(m_socket_devices);
    for (unsigned int d = 0; d < socket_devices_w->size(); ++d)
    {
      boost::intrusive_ptr<DnsSocket>& device_ptr(socket_devices_w->operator[](d));
      if (device_ptr)
        device_ptr->close();
    }
  }
  dns_resolver_ts::wat(m_dns_resolver)->close();
}

DnsResolver::DnsResolver() : m_dns_resolv_conf(nullptr), m_timer(&timed_out), m_hostname_cache(128), m_address_cache(128), m_getaddrinfo_memory_pool(32), m_getnameinfo_memory_pool(32)
{
  DoutEntering(dc::notice, "DnsResolver::DnsResolver()");
  Service const impossible_key("..", 244);      // Protocol 244 doesn't exist, nor does a service named "..".
  servicekey_to_port_cache_ts::wat(m_servicekey_to_port_cache)->set_empty_key(impossible_key);
}

DnsResolver::~DnsResolver()
{
  DoutEntering(dc::notice, "DnsResolver::~DnsResolver()");
  dns_resolver_ts::wat dns_resolver_w(m_dns_resolver);
  // Call DnsResolver::instance().close(); before leaving the scope of EventLoop.
  ASSERT(!dns_resolver_w->get());
  // Normally this shouldn't do anything, because it is already done by DnsResolver::instance().close().
  dns_resolver_w->close();
}

//static
void DnsResolver::dns_start_timer()
{
  DoutEntering(dc::notice, "DnsResolver::dns_start_timer()");
  instance().m_timer.start(threadpool::Interval<1, std::chrono::seconds>());
}

//static
void DnsResolver::dns_stop_timer()
{
  DoutEntering(dc::notice, "DnsResolver::dns_stop_timer()");
  instance().m_timer.stop();
}

//static
void DnsResolver::timed_out()
{
  DoutEntering(dc::notice, "DnsResolver::timed_out()");
  dns_resolver_ts::wat dns_resolver_w(instance().m_dns_resolver);
  dns_timed_out(dns_resolver_w->get());
  dns_resolver_w->run_dns();
}

void DnsResolver::LibdnsWrapper::run_dns()
{
  int error;

  if (!m_running)
  {
    // This is a serious error; but I'm not really sure how or if it could happen even if the code is bug free.
    Dout(dc::warning, "Calling LibdnsWrapper::run_dns() while not running?!");
    return;
  }

  if (m_dns_addrinfo)   // Are we doing a getaddrinfo lookup?
  {
    for (;;)
    {
      struct addrinfo* addrinfo;

      // Give CPU to libdns until it returns a non-zero value.
      if ((error = dns_ai_nextent(&addrinfo, m_dns_addrinfo)))
        break;

      // addrinfo is allocated on the heap (in dns_ai_setent in src/dns.c).
      m_current_addrinfo_lookup->result.add(addrinfo);
    }

    if (error == EAGAIN)
      return;

    if (error != ENOENT)
      m_current_addrinfo_lookup->error = error;

    Dout(dc::notice, "Calling set_ready()");
    m_current_addrinfo_lookup->set_ready();

    dns_ai_close(m_dns_addrinfo);
    m_dns_addrinfo = nullptr;
  }
  else                  // We're doing a getnameinfo lookup.
  {
    if ((error = dns_res_check(m_dns_resolver)))
    {
      if (error == EAGAIN)
        return;

      m_current_nameinfo_lookup->error = error;
    }
    else
    {
      struct dns_packet* P = dns_res_fetch(m_dns_resolver, &error);
      if (!P)
        m_current_nameinfo_lookup->error = error;
      else
      {
#if 0
        // Print packet header.
        Dout(dc::notice, ";; [HEADER]");
        Dout(dc::notice, ";;    qid : " << ntohs(dns_header(P)->qid));
        Dout(dc::notice, ";;     qr : " << ((dns_header(P)->qr)? "RESPONSE" : "QUERY") << '(' << dns_header(P)->qr << ')');
        Dout(dc::notice, ";; opcode : " << dns_stropcode((dns_opcode)dns_header(P)->opcode) << '(' << dns_header(P)->opcode << ')');
        Dout(dc::notice, ";;     aa : " << ((dns_header(P)->aa)? "AUTHORITATIVE" : "NON-AUTHORITATIVE") << '(' << dns_header(P)->aa << ')');
        Dout(dc::notice, ";;     tc : " << ((dns_header(P)->tc)? "TRUNCATED" : "NOT-TRUNCATED") << '(' << dns_header(P)->tc << ')');
        Dout(dc::notice, ";;     rd : " << ((dns_header(P)->rd)? "RECURSION-DESIRED" : "RECURSION-NOT-DESIRED") << '(' << dns_header(P)->rd << ')');
        Dout(dc::notice, ";;     ra : " << ((dns_header(P)->ra)? "RECURSION-ALLOWED" : "RECURSION-NOT-ALLOWED") << '(' << dns_header(P)->ra << ')');
        Dout(dc::notice, ";;  rcode : " << dns_strrcode(dns_p_rcode(P)) << '(' << dns_p_rcode(P) << ')');

        enum dns_section section = (dns_section)0;
#endif

        struct dns_rr rr;
        struct dns_rr_i rr_i;
        std::memset(&rr_i, 0, sizeof(rr_i));
        rr_i.sort = &dns_rr_i_packet;

        while (dns_rr_grep(&rr, 1, &rr_i, P, &error))
        {
#if 0
          // Print section headers.
          if (section != rr.section)
          {
            char section_str_buf[DNS_STRMAXLEN + 1];
            char const* section_str = dns_strsection(rr.section, section_str_buf, sizeof(section_str_buf));
            Dout(dc::notice, "");
            Dout(dc::notice, ";; [" << section_str << ":" << dns_p_count(P, rr.section) << "]");
            section = rr.section;
          }

          // Print section lines.
          char section_line_str[2 * sizeof(dns_any)];
          if (dns_rr_print(section_line_str, sizeof(section_line_str), &rr, P, &error))
            Dout(dc::notice, section_line_str);
#endif
          // Look for the answer section.
          if (rr.section != DNS_S_AN)
            continue;

          ASSERT(rr.class_ == DNS_C_IN);
          ASSERT(rr.type == DNS_T_PTR);

          union dns_any any;
          if ((error = dns_any_parse(dns_any_init(&any, sizeof(any)), &rr, P)))
            break;

          m_current_nameinfo_lookup->result = any.ptr.host;
          // Strip off the trailing dot.
          ASSERT(!m_current_nameinfo_lookup->result.empty());
          m_current_nameinfo_lookup->result.pop_back();

          break;
        }
        std::free(P);
      }
    }

    Dout(dc::notice, "Calling set_ready()");
    m_current_nameinfo_lookup->set_ready();
  }

  // At this point the LibdnsWrapper is no longer busy, provided this
  // is only checked while holding a lock on DnsResolver::m_dns_resolver.
  m_running = false;

  // FIXME: make this one queue? So that things get processed in order...
  if (!m_getaddrinfo_queue.empty())
  {
    auto& next_request = m_getaddrinfo_queue.front();
    start_getaddrinfo(next_request.first, next_request.second);
    m_getaddrinfo_queue.pop();
  }
  else if (!m_getnameinfo_queue.empty())
  {
    auto& next_request = m_getnameinfo_queue.front();
    start_getnameinfo(next_request);
    m_getnameinfo_queue.pop();
  }
}

void DnsResolver::LibdnsWrapper::close()
{
  dns_res_close(m_dns_resolver);
  m_dns_resolver = nullptr;
  dns_ai_close(m_dns_addrinfo);
  m_dns_addrinfo = nullptr;
}

void DnsResolver::HostnameCacheEntry::set_error_empty()
{
  // Don't overwrite a real error.
  ASSERT(error == 0);
  error = DNS_EEMPTY;
}

void DnsResolver::LibdnsWrapper::start_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
{
  m_current_addrinfo_lookup = new_cache_entry;
  // Call DnsResolver.instance().init(false) at the start of main() to initialize the resolver.
  ASSERT(m_dns_resolver);
  int error = 0;        // Must be set to 0.
  struct dns_addrinfo* addrinfo = dns_ai_open(m_current_addrinfo_lookup->str.c_str(), nullptr, (dns_type)0, hints.as_addrinfo(), m_dns_resolver, &error);
  if (!addrinfo)
    THROW_MALERT("dns_ai_open(\"[HOSTNAME]\") [with hints '[HINTS]'] returned \"[ERROR_MSG]\"",
        AIArgs("[HOSTNAME]", m_current_addrinfo_lookup->str)("[HINTS]", hints)("[ERROR_MSG]", dns_strerror(error)));
  // A previous request should already have been moved to its corresponding AddrInfoLookup object in run_dns(), before we get here again.
  ASSERT(m_current_addrinfo_lookup->result.empty());
  m_dns_addrinfo = addrinfo;
  m_running = true;
  run_dns();
}

void DnsResolver::LibdnsWrapper::start_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry)
{
  m_current_nameinfo_lookup = new_cache_entry;
  // Call DnsResolver.instance().init() at the start of main() to initialize the resolver.
  ASSERT(m_dns_resolver);
  int error = dns_res_submit(m_dns_resolver, new_cache_entry->arpa_str.c_str(), DNS_T_PTR, DNS_C_IN);
  if (error)
    THROW_MALERT("dns_res_submit(\"[ARPANAME]\") returned \"[ERROR_MSG]\"",
        AIArgs("[ARPANAME]", new_cache_entry->arpa_str)("[ERROR_MSG]", dns_strerror(error)));
  // m_dns_addrinfo is to nullptr at the same time that m_running is set to false (and we should never get here while m_running is already set).
  ASSERT(!m_dns_addrinfo);
  m_running = true;
  run_dns();
}

void DnsResolver::LibdnsWrapper::queue_getaddrinfo(std::shared_ptr<HostnameCacheEntry> const& new_cache_entry, AddressInfoHints const& hints)
{
  // Check if the dns lib is busy with another lookup (yeah, it doesn't support doing lookups in parallel).
  if (m_running)
    m_getaddrinfo_queue.emplace(new_cache_entry, hints);
  else
    start_getaddrinfo(new_cache_entry, hints);
}

void DnsResolver::LibdnsWrapper::queue_getnameinfo(std::shared_ptr<AddressCacheEntry> const& new_cache_entry)
{
  // Check if the dns lib is busy with another lookup (yeah, it doesn't support doing lookups in parallel).
  if (m_running)
    m_getnameinfo_queue.emplace(new_cache_entry);
  else
    start_getnameinfo(new_cache_entry);
}

std::shared_ptr<AddrInfoLookup> DnsResolver::queue_getaddrinfo(std::string&& hostname, uint16_t port, AddressInfoHints const& hints)
{
  DoutEntering(dc::notice, "DnsResolver::queue_getaddrinfo(\"" << hostname << "\", " << port << ", " << hints << ")");

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

  // If this was a new AddrInfoLookup, query the DNS server(s).
  if (new_cache_entry)
    dns_resolver_ts::wat(m_dns_resolver)->queue_getaddrinfo(*new_cache_entry_ptr, hints);

  return std::allocate_shared<AddrInfoLookup>(utils::Allocator<AddrInfoLookup,
      utils::NodeMemoryPool>(*getaddrinfo_memory_pool_ts::wat(m_getaddrinfo_memory_pool)), *new_cache_entry_ptr, port);
}

std::shared_ptr<NameInfoLookup> DnsResolver::getnameinfo(evio::SocketAddress const& address)
{
  DoutEntering(dc::notice, "DnsResolver::getnameinfo(" << address << ")");

  bool new_cache_entry;
  std::shared_ptr<AddressCacheEntry> const* new_cache_entry_ptr;
  {
    address_cache_ts::wat address_cache_w(m_address_cache);
    utils::Allocator<AddressCacheEntry, utils::NodeMemoryPool> address_cache_allocator(address_cache_w->memory_pool);
    evio::SocketAddress::arpa_buf_t buf;
    address.ptr_qname(buf);
    auto insert_result = address_cache_w->unordered_set.insert(std::allocate_shared<AddressCacheEntry>(address_cache_allocator, std::string(buf.data(), buf.size())));
    new_cache_entry_ptr = &*insert_result.first;
    new_cache_entry = insert_result.second;
  }
  Dout(dc::notice, (new_cache_entry ? "Insert into address cache took place." : "Found cached entry!"));

  // If this was a new NameInfoLookup, query the DNS server(s).
  if (new_cache_entry)
    dns_resolver_ts::wat(m_dns_resolver)->queue_getnameinfo(*new_cache_entry_ptr);

  return std::allocate_shared<NameInfoLookup>(utils::Allocator<NameInfoLookup,
      utils::NodeMemoryPool>(*getnameinfo_memory_pool_ts::wat(m_getnameinfo_memory_pool)), *new_cache_entry_ptr);
}

// Return the official protocol name of `protocol'.
// If protocol == 0, returns nullptr; otherwise if protocol doesn't exist, returns "unknown".
//static
char const* DnsResolver::protocol_str(in_proto_t protocol)
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
in_proto_t DnsResolver::protocol(char const* protocol_str)
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

uint16_t DnsResolver::port(Service const& key)
{
  uint16_t port;
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
SingletonInstance<resolver::DnsResolver> dummy __attribute__ ((__unused__));
} // namespace
