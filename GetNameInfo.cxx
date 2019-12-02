/**
 * resolver-task -- AIStatefulTask submodule - asynchronous hostname resolver.
 *
 * @file
 * @brief Implementation of GetNameInfo.
 *
 * @Copyright (C) 2018  Carlo Wood.
 *
 * RSA-1024 0x624ACAD5 1997-01-26                    Sign & Encrypt
 * Fingerprint16 = 32 EC A7 B6 AC DB 65 A6  F6 F6 55 DD 1C DC FF 61
 *
 * This file is part of resolver-task.
 *
 * Resolver-task is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Resolver-task is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with resolver-task.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "sys.h"
#include "GetNameInfo.h"

namespace task {

char const* GetNameInfo::state_str_impl(state_type run_state) const
{
  switch(run_state)
  {
    AI_CASE_RETURN(GetNameInfo_start);
    AI_CASE_RETURN(GetNameInfo_ready);
    AI_CASE_RETURN(GetNameInfo_done);
  }
  ASSERT(false);
  return "UNKNOWN STATE";
}

void GetNameInfo::initialize_impl()
{
  DoutEntering(dc::statefultask(mSMDebug), "GetNameInfo::initialize_impl() [" << (void*)this << "]");
  set_state(GetNameInfo_start);
  // This isn't going to work. Please call GetNameInfo::run() with a non-immediate handler,
  // for example resolver::DnsResolver::instance().get_handler();
  ASSERT(!default_is_immediate());
}

void GetNameInfo::done(resolver::DnsResolver::AddressCacheEntryReadyEvent const&)
{
  signal(1);
}

void GetNameInfo::multiplex_impl(state_type run_state)
{
  switch (run_state)
  {
    case GetNameInfo_start:
      wait_until([this]{ return m_result->is_ready(); }, 1, GetNameInfo_ready);
      break;
    case GetNameInfo_ready:
      set_state(GetNameInfo_done);
      // done() is not called by an engine, hence signal(1) is called by an 'immediate' handler.
      // Call yield() here to switch back to the default handler (which shouldn't be immediate),
      // before doing the call back. This is especially necessary when the call back attempts
      // to start a new DNS look up by calling run().
      if (is_immediate())       // Lets check it anway.
      {
        yield();
        break;
      }
      [[fallthrough]];
    case GetNameInfo_done:
      finish();
      break;
  }
}

} // namespace task
