/** $lic$
 * Copyright (C) 2015-2020 by Massachusetts Institute of Technology
 *
 * This file is part of libspin.
 *
 * libspin is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 2.
 *
 * libspin was developed as part of the Swarm architecture simulator. If you
 * use this software in your research, we request that you reference the Swarm
 * paper ("A Scalable Architecture for Ordered Parallelism", Jeffrey et al.,
 * MICRO-48, 2015) as the source of libspin in any publications that use this
 * software, and that you send us a citation of your work.
 *
 * libspin is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SPIN_H_
#define SPIN_H_

/* Public libspin interface */

#include <functional>
#include <stdint.h>
#include <tuple>
#include <vector>

#ifdef SPIN_BARE_PINH_INCLUDE
#include "pin.H"
#else
#include "pin/pin.H"
#endif

#define IARG_SPIN_THREAD_ID IARG_REG_VALUE, spin::__getTidReg()
// NOTE: We actually have no way to enforce constness, but have both defs to mirror Pin
#define IARG_SPIN_CONST_CONTEXT IARG_REG_VALUE, spin::__getContextReg()
#define IARG_SPIN_CONTEXT IARG_REG_VALUE, spin::__getContextReg()

namespace spin {
    // Types
    struct ThreadContext;  // opaque to tool
    typedef uint32_t ThreadId;
    typedef void (*CaptureCallback)(ThreadId tid, bool runsNext);
    typedef ThreadId (*UncaptureCallback)(ThreadId tid, ThreadContext* tc);
    typedef void (*ThreadCallback)(ThreadId tid);

    // Unlike UncaptureCallback, SyscallEnterCallback is (a) never delayed, and
    // (b) callback can re-steer the thread to avoid the syscall using
    // executeAt, and (c) return value indicates whether we should uncapture or
    // not (to support synchronous syscalls).
    typedef bool (*SyscallEnterCallback)(ThreadId tid, ThreadContext* tc);
    typedef void (*SyscallExitCallback)(ThreadId tid, ThreadContext* tc);

    typedef std::vector< std::tuple<INS, IPOINT, std::function<void()> > > CallpointVector;

    // Internal methods --- used by IARG macros
    REG __getContextReg();
    REG __getTidReg();
    REG __getSwitchReg();

    // Instrumentation: all analysis functions must be registered through this interface
    class TraceInfo {
        private:
            CallpointVector callpoints;
            CallpointVector switchpoints;

        public:
            template <typename ...Args>
            void insertCall(INS ins, IPOINT ipoint, AFUNPTR func, Args... args) {
                auto insLambda = [=] (Args... args) {
                    // TODO: I think call order should not be an issue anymore
                    INS_InsertCall(ins, ipoint, func, args..., IARG_END);
                };
                std::function<void()> f = std::bind(insLambda, args...);
                callpoints.push_back(std::make_tuple(ins, ipoint, f));
            }

            // Same as insertCall, but takes an IARGLIST instead of loose arguments
            // Unlike INS_InsertCall, caller should NOT manually free list
            void insertCallList(INS ins, IPOINT ipoint, AFUNPTR func, IARGLIST list) {
                auto insLambda = [=] () {
                    // TODO: I think call order should not be an issue anymore
                    INS_InsertCall(ins, ipoint, func, IARG_IARGLIST, list, IARG_END);
                    IARGLIST_Free(list);
                };
                callpoints.push_back(std::make_tuple(ins, ipoint, insLambda));
            }

            template <typename ...Args>
            void insertSwitchCall(INS ins, IPOINT ipoint, AFUNPTR func, Args... args) {
                auto insLambda = [=] (Args... args) {
                    INS_InsertCall(ins, ipoint, func, args..., IARG_RETURN_REGS, __getSwitchReg() /*jump target*/, IARG_END);
                };
                std::function<void()> f = std::bind(insLambda, args...);
                switchpoints.push_back(std::make_tuple(ins, ipoint, f));
            }

            // Same as insertCall, but takes an IARGLIST instead of loose arguments
            // Unlike INS_InsertCall, caller should NOT manually free list
            void insertSwitchCallList(INS ins, IPOINT ipoint, AFUNPTR func, IARGLIST list) {
                auto insLambda = [=] () {
                    INS_InsertCall(ins, ipoint, func, IARG_IARGLIST, list, IARG_RETURN_REGS, __getSwitchReg() /*jump target*/, IARG_END);
                    IARGLIST_Free(list);
                };
                switchpoints.push_back(std::make_tuple(ins, ipoint, insLambda));
            }

            friend void InstrumentTrace(TRACE trace, VOID* v);
            friend void Instrument(TRACE trace, const TraceInfo& pt);
    };

    typedef void (*TraceCallback)(TRACE, TraceInfo&);

    // Initialization
    void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb,
            CaptureCallback captureCb, UncaptureCallback uncaptureCb);
    void setSyscallEnterCallback(SyscallEnterCallback syscallEnterCb);
    void setSyscallExitCallback(SyscallExitCallback syscallExitCb);

    // Context querying/manipulation methods
    uint64_t getReg(const ThreadContext* tc, REG reg);
    void setReg(ThreadContext* tc, REG reg, uint64_t val);

    // NOTE: tid can be the running tid, but contexts should only be read and
    // modified from switchcalls!
    ThreadContext* getContext(ThreadId tid);

    // Thread blocking/unblocking
    void blockAfterSwitch(); /* block current thread immediately after the switchcall; must have other running threads */
    void blockIdleThread(ThreadId tid); /* thread must not be the running one */
    void unblock(ThreadId tid);

    // Force the currently-running switchcall to run again, even if we return
    // the same thread (returning a different thread will cause the switchcall
    // to run again the next time this thread is invoked, as usual)
    void loop();
    bool isLoopSet();
};

#endif  // SPIN_H_
