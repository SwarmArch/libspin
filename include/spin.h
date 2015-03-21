/** $lic$
 * Copyright (C) 2015 by Massachusetts Institute of Technology
 *
 * This file is part of libspin.
 *
 * libspin is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 2.
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
#include "pin/pin.H"

#ifdef SPIN_SLOW
#define IARG_SPIN_CONST_CONTEXT IARG_CONST_CONTEXT
#define IARG_SPIN_CONTEXT IARG_CONTEXT
#else
// Fast context macros to use in analysis routines
// NOTE: We actually have no way to enforce constness, but have both defs to mirror Pin
#define IARG_SPIN_CONST_CONTEXT IARG_REG_VALUE, spin::__getContextReg()
#define IARG_SPIN_CONTEXT IARG_REG_VALUE, spin::__getContextReg()
#endif
#define IARG_SPIN_THREAD_ID IARG_REG_VALUE, spin::__getTidReg()

namespace spin {
    // Types
    struct ThreadContext;  // opaque to tool
    typedef uint32_t ThreadId;
    typedef void (*CaptureCallback)(ThreadId tid, bool runsNext);
    typedef ThreadId (*UncaptureCallback)(ThreadId tid, ThreadContext* tc);
    typedef void (*ThreadCallback)(ThreadId tid);

    typedef std::vector< std::tuple<INS, IPOINT, std::function<void()> > > CallpointVector;

    // Internal methods --- used by IARG macros
#ifndef SPIN_SLOW
    REG __getContextReg();
#endif
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

            template <typename ...Args>
            void insertSwitchCall(INS ins, IPOINT ipoint, AFUNPTR func, Args... args) {
                auto insLambda = [=] (Args... args) {
                    INS_InsertCall(ins, ipoint, func, args..., IARG_RETURN_REGS, __getSwitchReg() /*jump target*/, IARG_END);
                };
                std::function<void()> f = std::bind(insLambda, args...);
                switchpoints.push_back(std::make_tuple(ins, ipoint, f));
            }

            friend void InstrumentTrace(TRACE trace, VOID* v);
            friend void Instrument(TRACE trace, const TraceInfo& pt);
    };

    typedef void (*TraceCallback)(TRACE, TraceInfo&);

    // Initialization
    void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb,
            CaptureCallback captureCb, UncaptureCallback uncaptureCb);

    // Context querying/manipulation methods
    uint64_t getReg(const ThreadContext* tc, REG reg);
    void setReg(ThreadContext* tc, REG reg, uint64_t val);
    //void saveContext(const ThreadContext* tc, CONTEXT* pinCtxt);
    //void loadContext(const CONTEXT* pinCtxt, ThreadContext* tc);

    // NOTE: tid must be != running tid, otherwise this context will be stale!
    ThreadContext* getContext(ThreadId tid);

    /* If you modify the current ThreadContext in a switchcall, you must call
     * this routine immmediately befoere returning from the switchcall to alter
     * the control flow and continue execution from somewhere else. This
     * function might or might not return, and you must change the PC;
     * supplying the same PC as the current PC may cause an infinite loop.
     * 
     * This is a wart in the interface to simplify and lower the overheads of
     * the slow-mode implementation. In fast mode, contexts are memory-backed
     * and can be modified from anywhere, and the PC can be modified in
     * switchcalls, so this does nothing but update the PC. But in slow mode,
     * thread contexts are just Pin CONTEXTs, which Pin builds on the fly and
     * discards after the analysis routine. For changes to take effect, we must
     * use PIN_ExecuteAt in these cases. Alternatively, we could be more
     * invasive and copy the context, pass that to the application, have getReg
     * and setReg flag changes to the running context, and use ExecuteAt
     * internally on that context copy, but that would be more complex and
     * expensive. Since we uese this sparingly, this is the faster option,
     * though the interface is ugly.
     *
     * TODO: Remove this function when the fast mode becomes reliable and we
     * start using it widely.
     */
    void executeAt(ThreadContext* tc, ADDRINT nextPc);

    // Thread blocking/unblocking
    void blockAfterSwitch(); /* block current thread immediately after the switchcall; must have other running threads */
    void blockIdleThread(ThreadId tid); /* thread must not be the running one */
    void unblock(ThreadId tid);
};

#endif  // SPIN_H_
