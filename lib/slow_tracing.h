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

#include "pin/pin.H"

#include <algorithm>
#include <array>
#include <vector>
#include <queue>
#include <cstdlib>
#include <random>
#include <string>

#include <iostream>
#include <set>
#include <map>
#include <sstream>
#include <unistd.h>

#ifndef SPIN_SLOW
#error "You must compile this file with SPIN_SLOW"
#endif

#define DEBUG(args...)
//#define DEBUG(args...) info(args)

namespace spin {

// Thread context state (2Kthreads is Pin's current limit)
#define MAX_THREADS 2048
std::array<CONTEXT, MAX_THREADS> contexts;

/* Tracing design in slow-mode SPIN (see the fast-mode comment first)
 *
 * Slow mode is ~100x slower than fast mode, but more robust and simpler.
 *
 * In slow mode, each normal analysis call works as-is without any extra
 * instrumentation. Each switchcall returns the next thread to run, and a
 * trailing SwitchHandler() uses SLOW PIN_ExecuteAt to switch to it.
 * 
 * Most of the smarts in slow-mode SPIN are in handling syscalls, which is
 * similar to fast-mode but without the context copies. As in fast mode,
 * a guard at the start of every trace handles captures, and syscalls are
 * prefaced with uncapture callbacks.
 */

#if 0
/* Tracing */

void Trace(TRACE trace, VOID *v) {
    // Order the trace's instructions
    std::vector<INS> idxToIns;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            idxToIns.push_back(ins);
        }
    }

    TraceInfo pt;
    pt.firstIns = idxToIns[0];
    pt.skipLeadingSwitchCall = INS_IsSyscall(pt.firstIns);
    traceCallback(trace, pt);

    if (!INS_IsSyscall(idxToIns[0])) {
        INS_InsertIfCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)RunTraceGuard,
                IARG_REG_VALUE, executorReg,
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertThenCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)TraceGuard,
                IARG_THREAD_ID, IARG_CONST_CONTEXT, 
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
    }

    // Syscall guard
    for (INS ins : idxToIns) {
        if (INS_IsSyscall(ins)) {
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)RunSyscallGuard,
                    IARG_REG_VALUE, executorReg,
                    IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)SyscallGuard,
                    IARG_THREAD_ID, IARG_CONST_CONTEXT, 
                    IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        }
    }

    // Switch handler
    // NOTE: For now, this is just a post-handler, but if we find we need to
    // modify the context in the switchcall (e.g., write arguments etc), we can
    // save the context first, pass our internal copy to the switchcall, then
    // run ExecuteAt.
    for (auto iip : pt.switchpoints) {
        INS ins = std::get<0>(iip);
        IPOINT ipoint = std::get<1>(iip);
        if (ipoint != IPOINT_BEFORE) {
            // We can probably do AFTER and TAKEN_BRANCH in slow mode, but
            // they're difficult to do in fast mode.
            panic("Switchcalls only support IPOINT_BEFORE for now");
        }

        if (ins == idxToIns[0] && INS_IsSyscall(ins)) continue;
        // Will be added right after the switchcall
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)NeedsSwitch,
                IARG_REG_VALUE, switchReg, IARG_END);
        INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR) SwitchHandler,
                IARG_THREAD_ID, IARG_CONST_CONTEXT, IARG_END);
    }
}

/* Public interface */

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, CaptureCallback captureCb, UncaptureCallback uncaptureCb) {
    for (auto& ts : threadStates) ts = UNCAPTURED;
    for (auto& wl : waitLocks) wl.lock();
    curTid = -1u;
    executorTid = -1u;
    executorInSyscall = false;
    blockAfterSwitchcall = false;
    capturedThreads = 0;

    traceCallback = traceCb;
    threadStartCallback = startCb;
    threadEndCallback = endCb;
    captureCallback = captureCb;
    uncaptureCallback = uncaptureCb;
    
    executorReg = PIN_ClaimToolRegister();
    switchReg = PIN_ClaimToolRegister();

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
}

uint64_t getReg(const ThreadContext* tc, REG reg) {
    return PIN_GetContextReg((const CONTEXT*)tc, reg);
}

void setReg(ThreadContext* tc, REG reg, uint64_t val) {
    PIN_SetContextReg((CONTEXT*)tc, reg, val);
}

void saveContext(const ThreadContext* tc, CONTEXT* pinCtxt) {
    PIN_SaveContext((const CONTEXT*)tc, pinCtxt);
}

void loadContext(const CONTEXT* pinCtxt, ThreadContext* tc) {
    PIN_SaveContext(pinCtxt, (CONTEXT*)tc);
}

ThreadContext* getContext(ThreadId tid) {
    assert(tid < MAX_THREADS);
    assert(threadStates[tid] == BLOCKED || threadStates[tid] == IDLE);
    return (ThreadContext*)&contexts[tid];
}

void executeAt(ThreadContext* tc, ADDRINT nextPc) {
    ADDRINT curPc = getReg(tc, REG_RIP);
    assert(nextPc != curPc);  // will enter an infinite loop otherwise
    setReg(tc, REG_RIP, nextPc);
    PIN_ExecuteAt((CONTEXT*)tc);
}

REG __getSwitchReg() {
    assert(traceCallback);  // o/w not initialized
    return switchReg;
}

void blockAfterSwitch() {
    assert(!blockAfterSwitchcall);
    blockAfterSwitchcall = true;  // honored by SwitchHandler
}

void blockIdleThread(ThreadId tid) {
    executorMutex.lock();
    assert(tid < MAX_THREADS);
    assert(threadStates[tid] == IDLE);
    assert(capturedThreads > 1);
    threadStates[tid] = BLOCKED;
    capturedThreads--;
    executorMutex.unlock();
}

void unblock(ThreadId tid) {
    executorMutex.lock();
    assert(tid < MAX_THREADS);
    assert(threadStates[tid] == BLOCKED);
    threadStates[tid] = IDLE;
    capturedThreads++;
    executorMutex.unlock();
}
#endif
}  // namespace spin
