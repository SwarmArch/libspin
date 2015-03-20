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

/* NOTE: This file must be included only from spin.cpp. It's not actually a
 * header (for performance and because this code is only used from one place)
 */

#ifndef SPIN_SLOW
#error "You must compile this file with SPIN_SLOW"
#endif

/* Tracing design in slow-mode SPIN (see the fast-mode comment first)
 *
 * Slow mode is ~100x slower than fast mode, but more robust and simpler.
 *
 * In slow mode, each normal analysis call works as-is without any extra
 * instrumentation. Each switchcall returns the next thread to run, and a
 * trailing switch handler uses SLOW PIN_ExecuteAt to switch to it.
 */

namespace spin {
// Thread context state
std::array<CONTEXT, MAX_THREADS> contexts;

ThreadContext* GetTC(ThreadId tid) {
    assert(tid < MAX_THREADS);
    return (ThreadContext*)&contexts[tid];
}

CONTEXT* GetPinCtxt(ThreadContext* tc) {
    return (CONTEXT*)tc;
}

void InitContext(const CONTEXT* ctxt, ThreadContext* tc) {
    PIN_SaveContext(ctxt, GetPinCtxt(tc));
}

void CoalesceContext(const CONTEXT* ctxt, ThreadContext* tc) {
    InitContext(ctxt, tc);
}

// Public context functions
uint64_t getReg(const ThreadContext* tc, REG reg) {
    return PIN_GetContextReg((const CONTEXT*)tc, reg);
}

void setReg(ThreadContext* tc, REG reg, uint64_t val) {
    PIN_SetContextReg((CONTEXT*)tc, reg, val);
}

void executeAt(ThreadContext* tc, ADDRINT nextPc) {
    ADDRINT curPc = getReg(tc, REG_RIP);
    assert(nextPc != curPc);  // will enter an infinite loop otherwise
    setReg(tc, REG_RIP, nextPc);
    PIN_ExecuteAt((CONTEXT*)tc);
}

}  // namespace spin
