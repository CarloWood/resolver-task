/**
 * resolver-task -- AIStatefulTask submodule - asynchronous hostname resolver.
 *
 * @file
 * @brief Resolve an IP number. Declaration of class GetNameInfo.
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

#pragma once

#include "statefultask/AIStatefulTask.h"
#include "NameInfoLookup.h"
#include "debug.h"
#include "events/Events.h"
#include <atomic>

namespace task {

/**
 * The resolver task.
 *
 * Before calling @link group_run run()@endlink, call init() to pass needed parameters.
 *
 * When the task finishes it calls the callback, use parameter _1,
 * (success) to check whether or not the task actually finished or
 * was canceled. The boolean is true when it resolved the IP number
 * and false if the task was aborted.
 *
 * Objects of this type can be reused multiple times, see
 * also the documentation of AIStatefulTask.
 *
 * Typical usage:
 *
 * @code
 * task::GetNameInfo* resolver = new task::GetNameInfo;
 *
 * resolver->init(socket_address);      // As usual, this initializes the task before running it; don't call init() multiple times.
 * resolver->run(...);                  // Start evio::SocketAddress lookup and pass callback; see AIStatefulTask.
 * @endcode
 *
 * The default behavior is to call the callback and then delete the GetNameInfo object.
 * It is allowed to call init() followed by run() from within the callback function
 * to start another look up though.
 *
 * In the callback / parent task use,
 *
 * @code
 * if (resolver->success())
 *   // Use resolver->get_result()
 * else
 *   // Use resolver->get_error()
 * @endcode
 */
class GetNameInfo : public AIStatefulTask
{
 protected:
  /// The base class of this task.
  using direct_base_type = AIStatefulTask;

  /// The different states of the stateful task.
  enum resolver_state_type {
    GetNameInfo_start = direct_base_type::state_end,
    GetNameInfo_ready,
    GetNameInfo_done
  };

 public:
  /// One beyond the largest state of this task.
  static constexpr state_type state_end = GetNameInfo_done + 1;

 private:
  std::shared_ptr<resolver::NameInfoLookup> m_result;
  events::RequestHandle<resolver::DnsResolver::AddressCacheEntryReadyEvent> m_handle;
  events::BusyInterface m_busy_interface;

 public:
  /// Construct an GetNameInfo object.
  GetNameInfo(CWDEBUG_ONLY(bool debug = false)) : AIStatefulTask(CWDEBUG_ONLY(debug))
    { DoutEntering(dc::statefultask(mSMDebug), "GetNameInfo() [" << (void*)this << "]"); }

  /**
   * Start the name lookup of IP address.
   *
   * @param socket_address The IP number to be resolved.
   */
  void init(evio::SocketAddress const& socket_address)
  {
    m_result = resolver::DnsResolver::instance().getnameinfo(socket_address);
    m_handle = m_result->event_server().request(*this, &GetNameInfo::done, m_busy_interface);
  }

  /**
   * Test if lookup was successful.
   *
   * Only call this after done() was called (aka, from the callback).
   *
   * @returns True if success (call get_result()) and false when failure (call get_error()).
   */
  bool success() const { return m_result->success(); }

  /**
   * Get the result.
   *
   * Only call this if success() returns true.
   *
   * @returns The canonical hostname as a std::string.
   */
  std::string const& get_result() const { return m_result->get_result(); }

  /**
   * Get the error.
   *
   * Only call this if success() returns false.
   *
   * @returns The error string.
   */
   char const* get_error() const { return m_result->get_error(); }

 protected:
  /// The destructor is protected; call finish() (or abort()), not delete.
  ~GetNameInfo() override { DoutEntering(dc::statefultask(mSMDebug), "~GetNameInfo() [" << (void*)this << "]"); m_handle.cancel(); }

  /// Implementation of state_str for run states.
  char const* state_str_impl(state_type run_state) const override;

  /// Run bs_initialize.
  void initialize_impl() override;

  /// Handle mRunState.
  void multiplex_impl(state_type run_state) override;

 private:
  // This is the callback for resolver::DnsResolver::AddressCacheEntry::ready_event.
  void done(resolver::DnsResolver::AddressCacheEntryReadyEvent const&);
};

} // namespace task
