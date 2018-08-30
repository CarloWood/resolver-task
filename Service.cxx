#include "sys.h"
#include "Service.h"
#include <iostream>
#include <cstring>

namespace resolver {

bool operator<(Service const& service1, Service const& service2)
{
  bool is_num1 = service1.is_numeric();
  bool is_num2 = service2.is_numeric();
  if (AI_LIKELY(is_num1 && is_num2))
    return false;       // If both are numeric then they are equal.
  if (is_num1 != is_num2)
    return is_num1;
  return strcmp(service1.m_name, service2.m_name) < 0;
}

std::ostream& operator<<(std::ostream& os, Service const& service)
{
  if (service.is_numeric())
    return os << 0;
  return os << '"' << service.get_name() << '"';
}

} // namespace resolver
