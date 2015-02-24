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
#include <assert.h>
#include <set>
#include <map>
#include <sstream>
#include <unistd.h>
#include <mutex>

#ifndef PMP_SLOW
#error "You must compile this file with PMP_SLOW"
#endif

#include "pmp.h"
#include "log.h"

namespace pmp {

// Thread context state (2Kthreads is Pin's current limit)
#define MAX_THREADS 2048
std::array<CONTEXT*, MAX_THREADS> contexts;

// FIXME: Shared with pmp.cpp!! Move to common point.
enum ThreadState  {
    UNCAPTURED, // Out in a syscall or other point out of our control. Will trip a capture point when it comes back to Pin; will trip before any other instrumentation function.
    IDLE,       // Runnable but not active
    RUNNING,    // Currently running
    // Transitions: start -> UNCAPTURED
    //              On capture points: UNCAPTURED -> {IDLE, RUNNING}
    //              On switchpoints: IDLE <-> RUNNING
    //              On uncapture points: RUNNING -> UNCAPTURED
};

// Executor state (all strictly protected by executorMutex)
std::array<ThreadState, MAX_THREADS> threadStates;
uint32_t executorTid;
uint32_t curTid;
bool executorInSyscall;
std::mutex executorMutex;

uint64_t pad[64]; // FIXME

REG switchReg;

// Callbacks, set on init
TraceCallback traceCallback = nullptr;
UncaptureCallback uncaptureCallback = nullptr;
ThreadCallback captureCallback = nullptr;
ThreadCallback threadStartCallback = nullptr;
ThreadCallback threadEndCallback = nullptr;

/* Capture, uncapture, and executor handling */

void ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    info("Thread %d started", tid);
    threadStartCallback(tid);
}

void ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    info("Thread %d finished", tid);
    assert(threadStates[tid] == UNCAPTURED);
    threadEndCallback(tid);
}

void TraceGuard() {
    // Try to become the executor. If we can't, spin till
    // (a) we get notified of a syscall, or (b)
    //
}

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
    pt.skipLeadingSwitchCall = false;
    traceCallback(trace, pt);
}

void SyscallEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
}

void SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //info("syscall exit");
    // dsm: The syscall might have changed ANYTHING. Do a full context write.
    /*ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    assert(tc);*/
}

/* Public interface */

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, ThreadCallback captureCb, UncaptureCallback uncaptureCb) {
    curTid = -1;

    traceCallback = traceCb;
    threadStartCallback = startCb;
    threadEndCallback = endCb;
    captureCallback = captureCb;
    uncaptureCallback = uncaptureCb;
    
    switchReg = PIN_ClaimToolRegister();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddSyscallEntryFunction(SyscallEnter, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
}

ThreadId getCurThreadId() {
    assert(curTid < MAX_THREADS);
    return curTid;
}

uint64_t getReg(const ThreadContext* tc, REG reg) {
    return PIN_GetContextReg((const CONTEXT*)tc, reg);
}

void setReg(ThreadContext* tc, REG reg, uint64_t val) {
    PIN_SetContextReg((CONTEXT*)tc, reg, val);
}

REG __getSwitchReg() {
    assert(traceCallback);  // o/w not initialized
    return switchReg;
}

}  // namespace pmp
