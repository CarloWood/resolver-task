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
#include "dns/src/dns.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"

unsigned int const buffer_max_packet_size = (dns_p_calcsize(512) + 63) & 63;    // Round up to multiple of 64 (640 bytes) for no reason.

//static
void AIResolver::ResolverDevice::dns_wants_to_write(void* user_data)
{
  Dout(dc::notice, "Calling want_to_write()");
}

//static
void AIResolver::ResolverDevice::dns_wants_to_read(void* user_data)
{
  Dout(dc::notice, "Calling want_to_write()");
}

//static
void AIResolver::ResolverDevice::dns_closed_fd(void* user_data)
{
  Dout(dc::notice, "Calling want_to_write()");
}

AIResolver::ResolverDevice::ResolverDevice() :
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

    if (!(m_dns_resolv_conf = dns_resconf_local(&error)))
      { error_function = "dns_resconf_local"; break; }

    if (!(hosts = dns_hosts_local(&error)))
      { error_function = "dns_hosts_local"; break; }

    if (!(hints = dns_hints_local(m_dns_resolv_conf, &error)))
      { error_function = "dns_hints_local"; break; }

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

std::shared_ptr<AILookup> AIResolver::do_request(std::string&& hostname, std::string&& servicename)
{
  DoutEntering(dc::notice, "AIResolver::do_request(\"" << hostname << "\", \"" << servicename << "\")");

  if (AI_UNLIKELY(!m_resolver_device))          // Only true the first call.
    m_resolver_device = new ResolverDevice;

  std::shared_ptr<AILookup> handle;
  {
    utils::Allocator<AILookup, utils::NodeMemoryPool> node_allocator(m_node_memory_pool);
    handle = std::allocate_shared<AILookup>(node_allocator, std::move(hostname), std::move(servicename));
  }

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
