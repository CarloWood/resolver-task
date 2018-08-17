/**
 * @file
 * @brief Implementation of AILookupTask.
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
#include "AILookupTask.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

char const* AILookupTask::state_str_impl(state_type run_state) const
{
  switch(run_state)
  {
    AI_CASE_RETURN(AILookupTask_start);
    AI_CASE_RETURN(AILookupTask_done);
  }
  ASSERT(false);
  return "UNKNOWN STATE";
}

void AILookupTask::done()
{
  mLookupFinished.store(true, std::memory_order_relaxed);
  signal(1);
}

void AILookupTask::multiplex_impl(state_type run_state)
{
  switch (run_state)
  {
    case AILookupTask_start:
      {
        struct addrinfo hints = { AI_V4MAPPED /*| AI_ADDRCONFIG*/, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0, nullptr, nullptr, nullptr };
        struct addrinfo* res;
        int err = getaddrinfo(mNodeName.c_str(), mServiceName.c_str(), &hints, &res);
        if (err != 0)
        {
          Dout(dc::warning, "getaddrinfo() returned \"" << gai_strerror(err) << "\".");
        }
        else
        {
          mResult = res;
        }
        freeaddrinfo(res);
        done();
#if 0
        if (err != 0)
        {
          if (err == EAI_AGAIN)
          {
          }
          else if (err == EAI_ALLDONE)
          {
            finish();
            break;
          }
          else if (err == EAI_INTR)
            break;
        }
#endif
        wait_until([&]{ return mLookupFinished.load(std::memory_order_relaxed); }, 1, AILookupTask_done);
        break;
      }
    case AILookupTask_done:
      {
        finish();
        break;
      }
  }
}

void AILookupTask::abort_impl()
{
  // ...
}
