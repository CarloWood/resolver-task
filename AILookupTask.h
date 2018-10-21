/**
 * @file
 * @brief Resolve a hostname. Declaration of class AILookupTask.
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

#pragma once

#include "statefultask/AIStatefulTask.h"
#include "AddressInfo.h"
#include "Lookup.h"
#include "debug.h"
#include <atomic>

/*!
 * @brief The resolver task.
 *
 * Before calling @link group_run run()@endlink, call getaddrinfo() to pass needed parameters.
 *
 * When the task finishes it calls the callback, use parameter _1,
 * (success) to check whether or not the task actually finished or
 * was cancelled. The boolean is true when it resolved the hostname
 * and false if the task was aborted.
 *
 * Objects of this type can be reused multiple times, see
 * also the documentation of AIStatefulTask.
 *
 * Typical usage:
 *
 * @code
 * AILookupTask* resolver = new AILookupTask;
 *
 * resolver->getaddrinfo("www.google.com", 80);  // As usual, this initializes the task before running it; don't call getaddrinfo() multiple times.
 * resolver->run(...);          // Start hostname look up and pass callback; see AIStatefulTask.
 * @endcode
 *
 * The default behavior is to call the callback and then delete the AILookupTask object.
 * It is allowed to call getaddrinfo() followed by run() from within the callback function
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
class AILookupTask : public AIStatefulTask
{
 protected:
  //! The base class of this task.
  using direct_base_type = AIStatefulTask;

  //! The different states of the stateful task.
  enum resolver_state_type {
    AILookupTask_start = direct_base_type::max_state,
    AILookupTask_ready,
    AILookupTask_done
  };

 public:
  //! One beyond the largest state of this task.
  static state_type constexpr max_state = AILookupTask_done + 1;

 private:
  std::shared_ptr<resolver::Lookup> m_result;
  events::RequestHandle<resolver::Resolver::HostnameCacheEntryReadyEvent> m_handle;
  events::BusyInterface m_busy_interface;

 public:
  /*!
   * @brief Construct an AILookupTask object.
   */
  AILookupTask( DEBUG_ONLY(bool debug = false) ) DEBUG_ONLY(: AIStatefulTask(debug))
    { DoutEntering(dc::statefultask(mSMDebug), "AILookupTask() [" << (void*)this << "]"); }

  /*!
   * @brief Start the lookup of hostname that needs to be resolved.
   *
   * @param node The hostname to be resolved.
   * @param port The port number of the end point.
   * @param hints Optional hints.
   */
  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      void>::type
  getaddrinfo(S1&& node, in_port_t port, resolver::AddressInfoHints const& hints = resolver::AddressInfoHints())
  {
    m_result = resolver::Resolver::instance().queue_getaddrinfo(std::forward<std::string>(node), port, hints);
    m_handle = m_result->event_server().request(*this, &AILookupTask::done, m_busy_interface);
  }

  /*!
   * @brief Start the lookup of hostname and service name that need to be resolved.
   *
   * @param node The hostname that needs to be resolved.
   * @param service The service name we want to connect or bind to.
   * @param hints Optional hints.
   */
  template<typename S1>
  typename std::enable_if<
      std::is_same<S1, std::string>::value || std::is_convertible<S1, std::string>::value,
      void>::type
  getaddrinfo(S1&& node, char const* service, resolver::AddressInfoHints const& hints = resolver::AddressInfoHints())
  {
    m_result = resolver::Resolver::instance().queue_getaddrinfo(std::forward<std::string>(node),
        resolver::Resolver::instance().port(resolver::Service(service, hints.as_addrinfo()->ai_protocol)), hints);
    m_handle = m_result->event_server().request(*this, &AILookupTask::done, m_busy_interface);
  }

  /*!
   * @brief Test if lookup was successful.
   *
   * Only call this after done() was called (aka, from the callback).
   *
   * @returns True if success (call get_result()) and false when failure (call get_error()).
   */
  bool success() const { return m_result->success(); }

  /*!
   * @brief Get the result.
   *
   * Only call this if success() returns true.
   *
   * @returns a AddressInfoList.
   */
  resolver::AddressInfoList const& get_result() const { return m_result->get_result(); }

  /*!
   * @brief Get the error.
   *
   * Only call this if success() returns false.
   *
   * @returns The error string.
   */
   char const* get_error() const { return m_result->get_error(); }

 protected:
  //! Call finish() (or abort()), not delete.
  ~AILookupTask() override { DoutEntering(dc::statefultask(mSMDebug), "~AILookupTask() [" << (void*)this << "]"); m_handle.cancel(); }

  //! Implemenation of state_str for run states.
  char const* state_str_impl(state_type run_state) const override;

  //! Handle mRunState.
  void multiplex_impl(state_type run_state) override;

 private:
  // This is the callback for resolver::Resolver::HostnameCacheEntry::ready_event.
  void done(resolver::Resolver::HostnameCacheEntryReadyEvent const&);
};
