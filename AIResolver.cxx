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
#include "evio/AddressInfo.h"
#include "dns/src/dns.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"

unsigned int const buffer_max_packet_size = (dns_p_calcsize(512) + 63) & 63;    // Round up to multiple of 64 (640 bytes) for no reason.

//static
void AIResolver::ResolverDevice::dns_wants_to_write(void* user_data)
{
  DoutEntering(dc::notice, "dns_wants_to_write()");
  ResolverDevice* self = static_cast<ResolverDevice*>(user_data);
  self->start_output_device();
}

//static
void AIResolver::ResolverDevice::dns_wants_to_read(void* user_data)
{
  DoutEntering(dc::notice, "dns_wants_to_read()");
  ResolverDevice* self = static_cast<ResolverDevice*>(user_data);
  self->start_input_device();
}

//static
void AIResolver::ResolverDevice::dns_closed_fd(void* user_data)
{
  DoutEntering(dc::notice, "dns_closed_fd()");
  ResolverDevice* self = static_cast<ResolverDevice*>(user_data);
  ASSERT(false); // When do we get here?
  RefCountReleaser releaser = self->close_input_device();
  releaser += self->close_output_device();
  ASSERT(self->is_dead());
}

AIResolver::ResolverDevice::ResolverDevice(bool recurse) :
    evio::InputDevice(new evio::InputBuffer),
    evio::OutputDevice(new evio::OutputBuffer),
    m_dns_resolv_conf(nullptr),
    m_dns_resolver(nullptr)
{
  DoutEntering(dc::notice, "AIResolver::ResolverDevice::ResolverDevice()");

  // Initialize dns.
  static struct dns_options const opts = { { nullptr, nullptr }, dns_options::DNS_LIBEVENT };
  int error = 0;
  char const* error_function = nullptr;
  struct dns_hosts* hosts = nullptr;
  struct dns_hints* hints = nullptr;

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

    if (!(m_dns_resolver = dns_res_open(m_dns_resolv_conf, hosts, hints, nullptr, &opts, &error)))
      { error_function = "dns_res_open"; break; }

    // Set callback functions.
    dns_set_so_hooks(m_dns_resolver, this, &dns_wants_to_write, &dns_wants_to_read, &dns_closed_fd);
    int fd = dns_udp_fd(m_dns_resolver);
    Dout(dc::notice, "The file descriptor of the UDP socket of the resolver is " << fd);
    init(fd);
    m_flags |= INTERNAL_FDS_DONT_CLOSE; // Let the closing be done by libdns.
  }
  while (0);
  if (error_function)
  {
    // It is OK to call these three with a nullptr.
    dns_hints_close(hints);
    dns_hosts_close(hosts);
    dns_resconf_close(m_dns_resolv_conf);
    // FIXME, throw exception instead.
    DoutFatal(dc::fatal, error_function << "(): " << dns_strerror(error));
  }
}

void AIResolver::ResolverDevice::write_to_fd(int fd)
{
  DoutEntering(dc::evio, "AIResolver::ResolverDevice::write_to_fd(" << fd << ")");
  stop_output_device();
  dns_so_is_writable(m_dns_resolver);
  run_dns();
}

void AIResolver::ResolverDevice::read_from_fd(int fd)
{
  DoutEntering(dc::evio, "AIResolver::ResolverDevice::read_from_fd(" << fd << ")");
  stop_input_device();
  dns_so_is_readable(m_dns_resolver);
  run_dns();
}

void AIResolver::ResolverDevice::run_dns()
{
  evio::AddressInfoList addrinfo_list(nullptr);
  for (;;)
  {
    // Give CPU to libdns.
    int error = dns_ai_nextent(&addrinfo_list.raw_ref(), m_addrinfo);

    if (error != 0)
      break;

    Dout(dc::notice, "Result: " << addrinfo_list);
  }
}

AIResolver::ResolverDevice::~ResolverDevice()
{
  DoutEntering(dc::notice, "AIResolver::ResolverDevice::~ResolverDevice()");
  // It is OK to call this with a nullptr.
  dns_res_close(m_dns_resolver);
}

evio::IOBase::RefCountReleaser AIResolver::ResolverDevice::closed()
{
  // close() was just called. Actually close the socket using a libdns call.
  // This function destroys everything, so set the pointers to nullptr just in case.
  dns_res_close(m_dns_resolver);
  m_dns_resolver = nullptr;
  m_dns_resolv_conf = nullptr;

  return evio::IOBase::RefCountReleaser();
}

void AIResolver::ResolverDevice::getaddrinfo(evio::AddressInfoHints const& hints, AILookup const* lookup)
{
  int error;
  m_addrinfo = dns_ai_open(lookup->get_hostname().c_str(), lookup->get_servicename().c_str(), (dns_type)0, hints.as_addrinfo(), m_dns_resolver, &error);
  ASSERT(m_addrinfo != nullptr);  // error will still be uninitialized in this case.
  Dout(dc::notice, "ResolverDevice::getaddrinfo: dns_ai_open returned " << m_addrinfo);
  evio::AddressInfoList addrinfo_list(nullptr);
  error = dns_ai_nextent(&addrinfo_list.raw_ref(), m_addrinfo);
  // libdns just called dns_wants_to_write, and then always returns DNS_EAGAIN.
  ASSERT(error == EAGAIN);
}

std::shared_ptr<AILookup> AIResolver::do_request(std::string&& hostname, std::string&& servicename)
{
  DoutEntering(dc::notice, "AIResolver::do_request(\"" << hostname << "\", \"" << servicename << "\")");

  if (AI_UNLIKELY(!m_resolver_device))                  // Only true the first call.
    m_resolver_device = new ResolverDevice(true);       // true = do recursive lookups.

  std::shared_ptr<AILookup> handle;
  {
    utils::Allocator<AILookup, utils::NodeMemoryPool> node_allocator(m_node_memory_pool);
    handle = std::allocate_shared<AILookup>(node_allocator, std::move(hostname), std::move(servicename));
  }

  evio::AddressInfoHints hints;
  m_resolver_device->getaddrinfo(hints, handle.get());

#if 0
  // Fake a lookup for now.
  evio::SocketAddress sa1("127.0.0.1:80");
  evio::SocketAddress sa2("127.0.0.2:80");
  evio::SocketAddressList list;
  list += sa1;
  list += sa2;
  handle->set_result(std::move(list));
#endif

  return handle;
}

namespace {
SingletonInstance<AIResolver> dummy __attribute__ ((__unused__));
} // namespace
