#include "sys.h"
#include "Service.h"
#include <iostream>
#include <cstring>

namespace resolver {

Service::Service(char const* name, in_proto_t protocol) : m_protocol(protocol)
{
  std::strncpy(m_name, name, max_service_name_length);
}

std::ostream& operator<<(std::ostream& os, Service const& service)
{
  os << "Service:{name:\"" << service.name() << "\", protocol:" << service.protocol() << '}';
  return os;
}

} // namespace resolver
