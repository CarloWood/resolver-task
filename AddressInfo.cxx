#include "sys.h"
#include "AddressInfo.h"
#include <iostream>

namespace resolver {
namespace {

std::string ai_flags_str(int flags)
{
  std::string flags_str;
  if (flags == 0)
    return "0";
  if ((flags & AI_PASSIVE))
    flags_str = "AI_PASSIVE|";
  if ((flags & AI_CANONNAME))
    flags_str += "AI_CANONNAME|";
  if ((flags & AI_NUMERICHOST))
    flags_str += "AI_NUMERICHOST|";
  if ((flags & AI_V4MAPPED))
    flags_str += "AI_V4MAPPED|";
  if ((flags & AI_ALL))
    flags_str += "AI_ALL|";
  if ((flags & AI_ADDRCONFIG))
    flags_str += "AI_ADDRCONFIG|";
  if ((flags & AI_NUMERICSERV))
    flags_str += "AI_NUMERICSERV|";
#ifdef __USE_GNU
  if ((flags & AI_IDN))
    flags_str += "AI_IDN|";
  if ((flags & AI_CANONIDN))
    flags_str += "AI_CANONIDN|";
  if ((flags & AI_IDN_ALLOW_UNASSIGNED))
    flags_str += "AI_IDN_ALLOW_UNASSIGNED|";
  if ((flags & AI_IDN_USE_STD3_ASCII_RULES))
    flags_str += "AI_IDN_USE_STD3_ASCII_RULES|";
#endif
  return flags_str.substr(0, flags_str.size() - 1);
}

std::string ai_family_str(int family)
{
  if (family == AF_INET)
    return "AF_INET";
  else if (family == AF_INET6)
    return "AF_INET6";
  return std::to_string(family);
}

std::string ai_socktype_str(int socktype)
{
  if (socktype == SOCK_STREAM)
    return "SOCK_STREAM";
  else if (socktype == SOCK_DGRAM)
    return "SOCK_DGRAM";
  return std::to_string(socktype);
}

std::string ai_protocol_str(int protocol)
{
  if (protocol == IPPROTO_TCP)
    return "IPPROTO_TCP";
  else if (protocol == IPPROTO_UDP)
    return "IPPROTO_UDP";
  return std::to_string(protocol);
}

} // namespace

std::ostream& operator<<(std::ostream& os, AddressInfoHints const& hints)
{
  os << "AddressInfoHints:{flags:" << ai_flags_str(hints.m_hints.ai_flags) <<
                       ", family:" << ai_family_str(hints.m_hints.ai_family) <<
                     ", socktype:" << ai_socktype_str(hints.m_hints.ai_socktype) <<
                     ", protocol:" << ai_protocol_str(hints.m_hints.ai_protocol);
  return os << '}';
}

std::ostream& operator<<(std::ostream& os, AddressInfo const& addrinfo)
{
  os << "AddressInfo:{flags:" << ai_flags_str(addrinfo.m_addrinfo->ai_flags) <<
                  ", family:" << ai_family_str(addrinfo.m_addrinfo->ai_family) <<
                ", socktype:" << ai_socktype_str(addrinfo.m_addrinfo->ai_socktype) <<
                ", protocol:" << ai_protocol_str(addrinfo.m_addrinfo->ai_protocol) <<
                 ", addrlen:" << addrinfo.m_addrinfo->ai_addrlen <<
                    ", addr:";
  if (addrinfo.m_addrinfo->ai_addr)
    os << evio::SocketAddress(addrinfo.m_addrinfo->ai_addr);
  else
    os << "nullptr";
  if (addrinfo.m_addrinfo->ai_canonname)
    os << ", canonname:\"" << addrinfo.m_addrinfo->ai_canonname << '"';
  os << ", next:";
  if (addrinfo.m_addrinfo->ai_next)
    os << '&' << addrinfo.next();
  else
    os << "nullptr";
  return os << '}';
}

void AddressInfoList::clear()
{
  while (m_addrinfo)
  {
    struct addrinfo* next_ai = m_addrinfo->ai_next;
    std::free(m_addrinfo);
    m_addrinfo = next_ai;
  }
}

void AddressInfoList::add(struct addrinfo* addrinfo)
{
  struct addrinfo** ptr = &m_addrinfo;
  while (*ptr)
    ptr = &(*ptr)->ai_next;
  *ptr = addrinfo;
}

//static
size_t AddressInfo::alloc_size(struct addrinfo* ai)
{
  size_t size = sizeof(struct addrinfo);
  int family = ai->ai_addr->sa_family;
  // Don't call this function otherwise.
  ASSERT(family == AF_INET || family == AF_INET6);
  size += (family == AF_INET) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
  size += ai->ai_canonname ? strlen(ai->ai_canonname) + 1 : 0;
  return size;
}

void AddressInfo::deep_copy(AddressInfo const& address_info)
{
  // Only use this function of default constructed objects, or call clear() first.
  ASSERT(!m_addrinfo);
  struct addrinfo** ptr = &m_addrinfo;
  struct addrinfo* from = address_info.m_addrinfo;
  do
  {
    size_t const size = alloc_size(from);
    *ptr = static_cast<struct addrinfo*>(std::malloc(size));
    std::memcpy(*ptr, from, size);
    // Can't have an ai_canonname without a sockaddr, right?
    ASSERT((*ptr)->ai_addr || !(*ptr)->ai_canonname);
    if ((*ptr)->ai_addr)
    {
      (*ptr)->ai_addr = reinterpret_cast<struct sockaddr*>(*ptr + 1);
      if ((*ptr)->ai_canonname)
      {
        int family = (*ptr)->ai_addr->sa_family;
        // Not supported.
        ASSERT(family == AF_INET || family == AF_INET6);
        (*ptr)->ai_canonname = reinterpret_cast<char*>((*ptr)->ai_addr) + ((family == AF_INET) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
      }
    }
    ptr = &(*ptr)->ai_next;
  }
  while ((from = *ptr));
}

} // namespace resolver
