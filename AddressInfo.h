#pragma once

#include "evio/SocketAddress.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iosfwd>
#include <cstring>
#include <cstdlib>

namespace resolver {

class AddressInfoHints
{
 private:
  struct addrinfo m_hints;

 public:
  AddressInfoHints(
      int flags = AI_V4MAPPED | AI_ADDRCONFIG,          // Bitwise-OR of one or more of the following flags:
                                                        //   AI_V4MAPPED, AI_ADDRCONFIG, AI_NUMERICHOST, AI_PASSIVE, AI_NUMERICSERV, AI_CANONNAME, AI_ALL,
                                                        //   AI_IDN, AI_CANONIDN, AI_IDN_ALLOW_UNASSIGNED or AI_IDN_USE_STD3_ASCII_RULES.
      int family = AF_UNSPEC,                           // AF_INET or AF_INET6. AF_UNSPEC means any address family.
      int socktype = 0,                                 // SOCK_STREAM or SOCK_DGRAM. 0 means any socket type.
      int protocol = 0) :                               // PF_INET or PF_INET6 (just leave this at 0 as there is only one protocol per family anyway).
    m_hints{ flags, family, socktype, protocol, 0, nullptr, nullptr, nullptr } { }

  struct addrinfo const* as_addrinfo() const { return &m_hints; }
};

class AddressInfo
{
 protected:
  struct addrinfo* m_addrinfo;

 protected:
  AddressInfo() : m_addrinfo(nullptr) { }
  AddressInfo(AddressInfo&& addrinfo) : m_addrinfo(addrinfo.m_addrinfo) { addrinfo.m_addrinfo = nullptr; }
  AddressInfo(struct addrinfo* addrinfo) : m_addrinfo(addrinfo) { }
  virtual ~AddressInfo() { }

  // Disallow (move) assignment.
  AddressInfo& operator=(AddressInfo const& addrinfo) = delete;

 public:
  bool empty() const { return !m_addrinfo; }
  AddressInfo next() const { return AddressInfo(m_addrinfo->ai_next); }
  evio::SocketAddress addr() const { return m_addrinfo->ai_addr; }

  int flags() const { return m_addrinfo->ai_flags; }
  int family() const { return m_addrinfo->ai_family; }
  int socktype() const { return m_addrinfo->ai_socktype; }
  int protocol() const { return m_addrinfo->ai_protocol; }
  AddressInfoHints hints() const { return AddressInfoHints(m_addrinfo->ai_flags, m_addrinfo->ai_family, m_addrinfo->ai_socktype, m_addrinfo->ai_protocol); }

  operator struct addrinfo*() { return m_addrinfo; }
  operator struct addrinfo const*() const { return m_addrinfo; }

  friend std::ostream& operator<<(std::ostream& os, AddressInfo const& addrinfo);
};

class AddressInfoList : public AddressInfo
{
 public:
  AddressInfoList(AddressInfoHints const& hints) : AddressInfo(static_cast<struct addrinfo*>(std::malloc(sizeof(struct addrinfo))))
    { std::memcpy(m_addrinfo, hints.as_addrinfo(), sizeof(struct addrinfo)); }
  AddressInfoList(AddressInfoList&& addrinfo) : AddressInfo(std::move(addrinfo)) { }
  AddressInfoList(struct addrinfo* addrinfo) : AddressInfo(addrinfo) { }
  AddressInfoList() { }
  ~AddressInfoList() { clear(); }

  // Only allow move assignment.
  AddressInfoList& operator=(AddressInfoList&& addrinfo) { m_addrinfo = addrinfo.m_addrinfo; addrinfo.m_addrinfo = nullptr; return *this; }

  char const* canonname() const { return m_addrinfo->ai_canonname; }
  struct addrinfo*& raw_ref() { return m_addrinfo; }

  void clear();
  void add(struct addrinfo* addrinfo);
};

} // namespace resolver
