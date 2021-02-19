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
 *
 * To support setReg(), the Pin context is saved wholesale before every
 * switchcall.
 */

namespace spin {
/* Thread context state */
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

void UpdatePinContext(ThreadContext* tc) {
    // In slow mode, the tc IS the pin context, so nothing to do
    // Fast mode copies all regs to the pin context
}

/* Public context functions */
uint64_t getReg(const ThreadContext* tc, REG reg) {
    if (REG_is_xmm_ymm_zmm(reg)) {
        uint64_t regval[MAX_QWORDS_PER_PIN_REG];
        PIN_GetContextRegval((const CONTEXT*)tc, reg, (unsigned char*)regval);
        // no fp conversion
        return regval[0];
    } else {
        return PIN_GetContextReg((const CONTEXT*)tc, reg);
    }
}

void setReg(ThreadContext* tc, REG reg, uint64_t val) {
    if (REG_is_xmm_ymm_zmm(reg)) {
        // only writes val into low eight bytes & clears rest of register;
        // no fp conversion
        uint64_t regval[MAX_QWORDS_PER_PIN_REG] = {val};
        PIN_SetContextRegval((CONTEXT*)tc, reg, (const unsigned char*)regval);
    } else {
        PIN_SetContextReg((CONTEXT*)tc, reg, val);
    }

    uint32_t tid = PIN_GetContextReg((CONTEXT*)tc, tidReg);
    if (tid != -1u) {
        // This is the live context
        NotifySetLiveReg();
        if (reg == REG_RIP) NotifySetPC(tid);
    }
}

/* Instrumentation */
void SwitchHandler(THREADID tid, ThreadContext* tc, uint64_t nextTid) {
    RecordSwitch(tid, tc, nextTid);

    CONTEXT* pinCtxt = GetPinCtxt(tc);
    PIN_SetContextReg(pinCtxt, tcReg, (ADDRINT)nullptr);
    PIN_SetContextReg(pinCtxt, tidReg, -1);

    ThreadContext* nextTc = GetTC(nextTid);
    CONTEXT* nextPinCtxt = GetPinCtxt(nextTc);
    PIN_SetContextReg(nextPinCtxt, tcReg, (ADDRINT)nextTc);
    PIN_SetContextReg(nextPinCtxt, tidReg, nextTid);

    DEBUG_SWITCH("Switching %lx -> %lx (%ld)", spin::getReg(tc, REG_RIP), spin::getReg(nextTc, REG_RIP), nextTid);

    PIN_ExecuteAt(nextPinCtxt);
}

void Instrument(TRACE trace, const TraceInfo& pt) {
    INS firstIns = BBL_InsHead(TRACE_BblHead(trace));

    // Add switchcalls and switch handlers
    // NOTE: For now, this is just a post-handler, but if we find we need to
    // modify the context in the switchcall (e.g., write arguments etc), we can
    // save the context first, pass our internal copy to the switchcall, then
    // run ExecuteAt.
    for (auto iip : pt.switchpoints) {
        INS ins = std::get<0>(iip);
        IPOINT ipoint = std::get<1>(iip);
        std::function<void()> ifun = std::get<2>(iip);
        if (ipoint != IPOINT_BEFORE) {
            // We can probably do AFTER and TAKEN_BRANCH in slow mode, but
            // they're difficult to do in fast mode.
            panic("Switchcalls only support IPOINT_BEFORE for now");
        }

        if (ins == firstIns && ipoint == IPOINT_BEFORE && INS_IsSyscall(ins)) continue;
        // First, save the context
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InitContext,
                IARG_CONST_CONTEXT, IARG_REG_VALUE, tcReg, IARG_END);
        // Then, run the switchcall...
        ifun();
        // ...then the switch handler
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)NeedsSwitch,
                IARG_REG_VALUE, tidReg,
                IARG_REG_VALUE, switchReg, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)SwitchHandler,
                IARG_THREAD_ID,
                IARG_REG_VALUE, tcReg,
                IARG_REG_VALUE, switchReg, IARG_END);
    }


    // Add normal calls
    for (auto iip : pt.callpoints) {
        INS ins = std::get<0>(iip);
        IPOINT ipoint = std::get<1>(iip);
        std::function<void()> ifun = std::get<2>(iip);

        if (ins == firstIns && ipoint == IPOINT_BEFORE && INS_IsSyscall(ins)) continue;

        ifun();
    }
}

}  // namespace spin
