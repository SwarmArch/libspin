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

#ifndef _SPIN_H_
#define _SPIN_H_

/* Public libspin interface */

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
#define IARG_SPIN_THREAD_ID IARG_REG_VALUE, spin::__getSwitchReg()

namespace spin {
    // Types
    struct ThreadContext;  // opaque to tool
    typedef uint32_t ThreadId;
    typedef void (*CaptureCallback)(ThreadId tid, bool runsNext);
    typedef ThreadId (*UncaptureCallback)(ThreadId tid, ThreadContext* tc);
    typedef void (*ThreadCallback)(ThreadId tid);

    typedef std::vector< std::tuple<INS, IPOINT> > CallpointVector;

    // Internal methods --- used by IARG macros
#ifndef SPIN_SLOW
    REG __getContextReg();
#endif
    REG __getSwitchReg();

    // Instrumentation: all analysis functions must be registered through this interface
    class TraceInfo {
        private:
            CallpointVector callpoints;
            CallpointVector switchpoints;
            INS firstIns;
            bool skipLeadingSwitchCall;

        public:
            template <typename ...Args>
            void insertCall(INS ins, IPOINT ipoint, AFUNPTR func, Args... args) {
                callpoints.push_back(std::make_tuple(ins, ipoint));
                INS_InsertCall(ins, ipoint, func, args..., IARG_CALL_ORDER, CALL_ORDER_DEFAULT+1 /* always run after switchcalls and their internal handlers */, IARG_END);
            }

            template <typename ...Args>
            void insertSwitchCall(INS ins, IPOINT ipoint, AFUNPTR func, Args... args) {
                switchpoints.push_back(std::make_tuple(ins, ipoint));
                if (ins == firstIns && ipoint == IPOINT_BEFORE && skipLeadingSwitchCall) return;
                INS_InsertCall(ins, ipoint, func, args..., IARG_RETURN_REGS, __getSwitchReg() /*jump target*/, /*IARG_CALL_ORDER, CALL_ORDER_DEFAULT-1,*/ IARG_END);
            }

            friend void Trace(TRACE trace, VOID* v);
    };

    typedef void (*TraceCallback)(TRACE, TraceInfo&);

    // Initialization
    void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb,
            CaptureCallback captureCb, UncaptureCallback uncaptureCb);

    // Context querying/manipulation methods
    uint64_t getReg(const ThreadContext* tc, uint32_t reg);
    void setReg(ThreadContext* tc, uint32_t reg, uint64_t val);

    // Thread blocking/unblocking
    void blockAfterSwitch(); /* block current thread immediately after the switchcall; must have other running threads */
    void blockIdleThread(ThreadId tid); /* thread must not be the running one */
    void unblock(ThreadId tid);
};



#endif /* _SPIN_H_ */