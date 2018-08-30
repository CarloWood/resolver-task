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
#include "Resolver.h"
#include "dns/src/dns.h"
#include "threadsafe/aithreadsafe.h"
#include "utils/NodeMemoryPool.h"

namespace resolver {

unsigned int const buffer_max_packet_size = (dns_p_calcsize(512) + 63) & 63;    // Round up to multiple of 64 (640 bytes) for no reason.

Resolver::SocketDevice::SocketDevice() :
  evio::InputDevice(nullptr), evio::OutputDevice(nullptr)       // SocketDevice doesn't use (our) buffers.
{
  DoutEntering(dc::notice, "Resolver::SocketDevice::SocketDevice()");
}

//static
void* Resolver::SocketDevice::dns_created_socket(int fd)
{
  DoutEntering(dc::notice, "SocketDevice::dns_created_socket(" << fd << ")");
  SocketDevice* resolver_device = new SocketDevice();
  resolver_device->init(fd);
  resolver_device->m_flags |= INTERNAL_FDS_DONT_CLOSE; // Let the closing be done by libdns.
  // Increment ref count to stop this SocketDevice from being deleted while being used by libdns.
  intrusive_ptr_add_ref(resolver_device);
  Dout(dc::io, "Incremented ref count (now " << resolver_device->ref_count() << ") [" << (void*)static_cast<IOBase*>(resolver_device) << ']');
  return resolver_device;
}

//static
void Resolver::SocketDevice::dns_wants_to_write(void* user_data)
{
  DoutEntering(dc::notice, "dns_wants_to_write()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->start_output_device();
}

//static
void Resolver::SocketDevice::dns_wants_to_read(void* user_data)
{
  DoutEntering(dc::notice, "dns_wants_to_read()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  self->start_input_device();
}

//static
void Resolver::SocketDevice::dns_closed_fd(void* user_data)
{
  DoutEntering(dc::notice, "dns_closed_fd()");
  SocketDevice* self = static_cast<SocketDevice*>(user_data);
  ASSERT(false); // When do we get here?
  RefCountReleaser releaser;
  // Decrement ref count again (after incrementing it in dns_created_socket) now that libdns is done with it.
  releaser = self;
  releaser += self->close_input_device();
  releaser += self->close_output_device();
  ASSERT(self->is_dead());
}

void Resolver::SocketDevice::write_to_fd(int fd)
{
  DoutEntering(dc::evio, "Resolver::SocketDevice::write_to_fd(" << fd << ")");
  stop_output_device();
  dns_so_is_writable(Resolver::instance().m_dns_resolver, this);
  Resolver::instance().run_dns();
}

void Resolver::SocketDevice::read_from_fd(int fd)
{
  DoutEntering(dc::evio, "Resolver::SocketDevice::read_from_fd(" << fd << ")");
  stop_input_device();
  dns_so_is_readable(Resolver::instance().m_dns_resolver, this);
  Resolver::instance().run_dns();
}

void Resolver::init(bool recurse)
{
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

    // Set callback functions; this calls dns_created_socket for the already created UDP socket before it returns.
    dns_set_so_hooks(m_dns_resolver, &SocketDevice::dns_created_socket, &SocketDevice::dns_wants_to_write, &SocketDevice::dns_wants_to_read, &SocketDevice::dns_closed_fd);
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

Resolver::~Resolver()
{
  // It is OK to call this with a nullptr.
  dns_res_close(m_dns_resolver);
}

void Resolver::run_dns()
{
  int error;
  for (;;)
  {
    struct addrinfo* addrinfo;

    // Give CPU to libdns until it returns a non-zero value.
    if ((error = dns_ai_nextent(&addrinfo, m_dns_addrinfo)))
      break;

    m_addrinfo.add(addrinfo);
  }

  // This sets m_addrinfo to null again - allowing for the next lookup to start.
  if (error == ENOENT)
    m_lookup->set_result(std::move(m_addrinfo));
  else if (error != EAGAIN)
  {
    m_lookup->set_error(error);
    m_addrinfo.clear();
  }
}

Resolver::SocketDevice::~SocketDevice()
{
  DoutEntering(dc::notice, "Resolver::SocketDevice::~SocketDevice()");
}

bool Resolver::CacheEqualTo::operator()(std::shared_ptr<Lookup> const& lookup1, std::shared_ptr<Lookup> const& lookup2) const
{
  // Assuming we only compare Lookup objects whose hash is equal, it is
  // already pretty likely that they are equal and we will have to compare
  // everything; if they are not equal then it is more likely than normal
  // that the service and/or hints are unequal; and because those are the
  // fastest to compare we start with those.
  return lookup1->get_hints() == lookup2->get_hints() &&
         lookup1->get_service().is_cache_equal_to(lookup2->get_service()) &&    // Do is_cache_equal_to first assuming the most likely: that they are both numeric.
         lookup1->get_hostname() == lookup2->get_hostname();
}

std::shared_ptr<Lookup> Resolver::queue_request(std::string&& hostname, Service const& service, AddressInfoHints const& hints)
{
  DoutEntering(dc::notice, "Resolver::queue_request(\"" << hostname << "\", " << service << ", " << hints << ")");

  utils::Allocator<Lookup, utils::NodeMemoryPool> node_allocator(m_node_memory_pool);
  auto insert_result = m_cache.insert(std::allocate_shared<Lookup>(node_allocator, std::move(hostname), service, hints.hash_seed()));

  m_lookup = *insert_result.first;

  // If this was a new Lookup, query the DNS server(s).
  if (insert_result.second)
  {
    Dout(dc::notice, "Insert into cache took place.");
    // Call Resolver.instance().init() at the start of main() to initialize the resolver.
    ASSERT(m_dns_resolver);

    int error = 0;        // Must be set to 0.
    char const* service_name = m_lookup->get_service().is_numeric() ? "0" : m_lookup->get_service().get_name();
    m_dns_addrinfo = dns_ai_open(m_lookup->get_hostname().c_str(), service_name, (dns_type)0, hints.as_addrinfo(), m_dns_resolver, &error);

    // FIXME: throw error.
    if (!m_dns_addrinfo)
      DoutFatal(dc::fatal, dns_strerror(error) << '.');
    // A previous request should already have been moved to its corresponding Lookup object in run_dns(), before we get here again.
    ASSERT(m_addrinfo.empty());

    // Run libdns to actually get things started.
    run_dns();
  }
  else
    Dout(dc::notice, "Found cached entry!");

  return m_lookup;
}

} // namespace resolver

namespace {
SingletonInstance<resolver::Resolver> dummy __attribute__ ((__unused__));
} // namespace