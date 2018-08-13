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

char const* AIResolver::state_str_impl(state_type run_state) const
{
  switch(run_state)
  {
    AI_CASE_RETURN(AIResolver_start);
    AI_CASE_RETURN(AIResolver_done);
  }
  ASSERT(false);
  return "UNKNOWN STATE";
}

void AIResolver::done()
{
  mLookupFinished.store(true, std::memory_order_relaxed);
  signal(1);
}

void AITimer::multiplex_impl(state_type run_state)
{
  switch (run_state)
  {
    case AIResolver_start:
      {
        // ...
	wait_until([&]{ return mLookupFinished.load(std::memory_order_relaxed); }, 1, AIResolver_done);
        break;
      }
    case AIResolver_done:
      {
        finish();
        break;
      }
  }
}

void AITimer::abort_impl()
{
  // ...
}
