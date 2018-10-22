/**
 * @file
 * @brief Implementation of GetAddrInfo.
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
#include "GetAddrInfo.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace task {

char const* GetAddrInfo::state_str_impl(state_type run_state) const
{
  switch(run_state)
  {
    AI_CASE_RETURN(GetAddrInfo_start);
    AI_CASE_RETURN(GetAddrInfo_ready);
    AI_CASE_RETURN(GetAddrInfo_done);
  }
  ASSERT(false);
  return "UNKNOWN STATE";
}

void GetAddrInfo::done(resolver::Resolver::HostnameCacheEntryReadyEvent const&)
{
  signal(1);
}

void GetAddrInfo::multiplex_impl(state_type run_state)
{
  switch (run_state)
  {
    case GetAddrInfo_start:
      wait_until([this]{ return m_result->is_ready(); }, 1, GetAddrInfo_ready);
      break;
    case GetAddrInfo_ready:
      set_state(GetAddrInfo_done);
      // done() is not called by an engine, hence signal(1) is called by an 'immediate' handler.
      // Call yield() here to switch back to the default handler (which shouldn't be immediate),
      // before doing the call back. This is especially necessary when the call back attempts
      // to start a new DNS look up by calling run().
      if (is_immediate())       // Lets check it anway.
      {
        yield();
        break;
      }
      /* FALL-THROUGH */
    case GetAddrInfo_done:
      finish();
      break;
  }
}

} // namespace task
