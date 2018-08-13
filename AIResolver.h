/**
 * @file
 * @brief Resolve a hostname. Declaration of class AIResolver.
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

#include "AIStatefulTask.h"
#include <atomic>

/*!
 * @brief The resolver task.
 *
 * Before calling @link group_run run()@endlink, call set_hostname() to pass needed parameters.
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
 * AIResolver* resolver = new AIResolver;
 *
 * resolver->set_hostname("www.google.com");
 * resolver->run(...);          // Start hostname look up and pass callback; see AIStatefulTask.
 * @endcode
 *
 * The default behavior is to call the callback and then delete the AIResolver object.
 * You can call run(...) with parameters from the callback function to do another look up.
 */
class AIResolver : public AIStatefulTask
{
 protected:
  //! The base class of this task.
  using direct_base_type = AIStatefulTask;

  //! The different states of the stateful task.
  enum resolver_state_type {
    AIResolver_start = direct_base_type::max_state,
    AIResolver_done
  };

 public:
  //! One beyond the largest state of this task.
  static state_type constexpr max_state = AIResolver_done + 1;

 private:
  std::atomic_bool mLookupFinished;     //!< Set to true after the hostname lookup finished.
  std::string mHostname;                //!< Input variable: the hostname that needs to be resolved.

 public:
  /*!
   * @brief Construct an AIResolver object.
   */
  AIResolver(DEBUG_ONLY(bool debug = false)) :
#ifdef CWDEBUG
    AIStatefulTask(debug),
#endif
    mLoopupFinished(false) { DoutEntering(dc::statefultask(mSMDebug), "AIResolver() [" << (void*)this << "]"); }

  /*!
   * @brief Set the hostname that needs to be resolved.
   *
   * @param hostname The hostname to be resolved.
   *
   * Call abort() at any time to stop the resolver (and delete the AIResolver object).
   */
  void set_hostname(std::string hostname) { mHostname = hostname; }

  /*!
   * @brief Get the hostname.
   *
   * @returns the hostname that was set by set_hostname.
   */
  std::string const& get_hostname() const { return mHostname; }

 protected:
  //! Call finish() (or abort()), not delete.
  ~AIResolver() override { DoutEntering(dc::statefultask(mSMDebug), "~AIResolver() [" << (void*)this << "]"); }

  //! Implemenation of state_str for run states.
  char const* state_str_impl(state_type run_state) const override;

  //! Handle mRunState.
  void multiplex_impl(state_type run_state) override;

  //! Handle aborting from current bs_run state.
  void abort_impl() override;

 private:
  // This is the callback for ....
  void done();
};
