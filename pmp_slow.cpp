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
std::array<CONTEXT, MAX_THREADS> contexts;

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
std::array<std::mutex, MAX_THREADS> waitLocks;
uint32_t executorTid;
uint32_t curTid;
uint32_t capturedThreads;
bool executorInSyscall;
std::mutex executorMutex;

uint64_t pad[64]; // FIXME

REG executorReg;
REG switchReg;

// Callbacks, set on init
TraceCallback traceCallback = nullptr;
UncaptureCallback uncaptureCallback = nullptr;
ThreadCallback captureCallback = nullptr;
ThreadCallback threadStartCallback = nullptr;
ThreadCallback threadEndCallback = nullptr;

/* Tracing design in slow-mode PMP (see the fast-mode comment first)
 *
 * Slow-mode PMP is what you use when fast-mode PMP craps itself and nothing
 * works and you hate x86 and just want your tool to run, even if it's
 * 100x slower.
 *
 * Therefore, slow-mode PMP is pretty simple: Each normal call works as-is
 * without any extra instrumentation. Each switchcall returns the next thread
 * to run, and a trailing SwitchHandler() calls SLOW SaveContext and ExecuteAt
 * to switch to it.
 * 
 * Most of the smarts in slow-mode PMP are in handling syscalls, which is
 * similar to fast-mode but without the context copies. As in fast mode,
 * a guard at the start of every trace handles captures, and syscalls are
 * prefaced with uncapture callbacks.
 */

/* Capture, uncapture, and executor handling */

void ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    info("Thread %d started", tid);
    threadStartCallback(tid);
    assert(threadStates[tid] == UNCAPTURED);
    PIN_SetContextReg(ctxt, executorReg, 0);  // will be captured immediately
}

void ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    info("Thread %d finished", tid);
    assert(threadStates[tid] == UNCAPTURED);
    threadEndCallback(tid);
}

/* Tracing sequence*/

// Helper method for guards. Must be called with executorMutex held
void UncaptureAndSwitch() {
    uint64_t nextTid = uncaptureCallback(curTid, (ThreadContext*)&contexts[curTid]);
    capturedThreads--;
    assert(nextTid < MAX_THREADS);
    assert(threadStates[curTid] == RUNNING);
    threadStates[curTid] = UNCAPTURED;
    curTid = nextTid;
    assert(threadStates[curTid] == IDLE);
    threadStates[curTid] = RUNNING;
}


uint64_t RunTraceGuard(uint64_t executor) {
    return !executor;
}

// Runs only if we're coming back from a syscall
void TraceGuard(THREADID tid, const CONTEXT* ctxt) {
    executorMutex.lock();
    PIN_SaveContext(ctxt, &contexts[tid]);
    
    if (threadStates[tid] == RUNNING) {
        // We did not yield executor role when we ran the syscall, so keep
        // going as usual
        assert(executorTid == tid);
        assert(curTid == tid);
        assert(capturedThreads == 1);
        PIN_SetContextReg(&contexts[tid], executorReg, 1);
        PIN_ExecuteAt(&contexts[tid]);
    }

    assert(threadStates[tid] == UNCAPTURED);
    captureCallback(tid);
    capturedThreads++;
    threadStates[tid] = IDLE;

    if (capturedThreads == 1) {
        // We're the first! Make us run
        threadStates[tid] = RUNNING;
        assert(curTid == -1u);
        curTid = tid;
    }

    if (executorInSyscall) {
        assert(curTid == executorTid);
        assert(capturedThreads == 2);  // the non-uncaptured executor and us
        // Do delayed uncapture
        UncaptureAndSwitch();
        executorTid = -1u;
    }

    // If somebody else is the executor, wait until we're woken up, either
    // because we need to run a syscall or become the executor
    while (executorTid != -1u) {
        executorMutex.unlock();
        waitLocks[tid].lock();
        executorMutex.lock();
        if (threadStates[tid] == UNCAPTURED) {
            // Take syscall
            executorMutex.unlock();
            PIN_SetContextReg(&contexts[tid], executorReg, 0);
            PIN_ExecuteAt(&contexts[tid]);
        } else if (executorTid == -1u) {
            // NOTE: Due to wakeups interleaving with uncaptures, we can have
            // multiple threads going for the executor. For example, this
            // thread could have been woken up to claim executor, but a thread
            // that came out of a syscall got it first. Thus waking up does not
            // automatically mean executorTid == -1u, so we check.
            break;
        }
    }

    assert(executorTid == -1u);

    // Become executor
    executorTid = tid;
    assert(curTid < MAX_THREADS);
    executorMutex.unlock();
    PIN_SetContextReg(&contexts[curTid], executorReg, 1);
    PIN_ExecuteAt(&contexts[curTid]);
}

uint64_t RunSyscallGuard(uint64_t executor) {
    return executor;
}

void SyscallGuard(THREADID tid, const CONTEXT* ctxt) {
    executorMutex.lock();
    assert(executorTid == tid);
    PIN_SaveContext(ctxt, &contexts[curTid]);

    // Three possibilities:
    if (curTid != tid) {
        // 1. We need to ship off this syscall and move on to another thread
        assert(capturedThreads >= 2);  // both us and the tid we're running must be captured
        uint32_t wakeTid = curTid;
        UncaptureAndSwitch();  // changes curTid
        waitLocks[wakeTid].unlock();  // wake syscall taker
        executorMutex.unlock();
        PIN_SetContextReg(&contexts[curTid], executorReg, 1);
        PIN_ExecuteAt(&contexts[curTid]);
    } else {
        // We ourselves need to take the syscall...
        if (capturedThreads >= 2) {
            // 2. Wake up another idle thread to continue execution
            uint32_t wakeTid = MAX_THREADS;
            for (uint32_t t = 0; t < MAX_THREADS; t++) {
                if (threadStates[t] == IDLE) {
                    wakeTid = t;
                    break;
                }
            }
            assert(wakeTid < MAX_THREADS);
            assert(wakeTid != tid);
            UncaptureAndSwitch();  // changes curTid
            executorTid = -1u;
            waitLocks[wakeTid].unlock();  // wake new executor
        } else {
            // 3. We're the only captured thread, so if we uncaptured ourselves
            // the tool would run out of threads. Instead, let the first
            // captured thread do a delayed uncapture (or we'll do one)
            executorInSyscall = true;
        }
        
        executorMutex.unlock();
        // Take our syscall
        PIN_SetContextReg(&contexts[tid], executorReg, 0);
        PIN_ExecuteAt(&contexts[tid]);
    }
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
            INS_InsertIfCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)RunSyscallGuard,
                    IARG_REG_VALUE, executorReg,
                    IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            INS_InsertThenCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)SyscallGuard,
                    IARG_THREAD_ID, IARG_CONST_CONTEXT, 
                    IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        }
    }
}

#if 0
void SyscallEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
}

void SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //info("syscall exit");
    // dsm: The syscall might have changed ANYTHING. Do a full context write.
    /*ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    assert(tc);*/
}
#endif

/* Public interface */

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, ThreadCallback captureCb, UncaptureCallback uncaptureCb) {
    for (auto& ts : threadStates) ts = UNCAPTURED;
    for (auto& wl : waitLocks) wl.lock();
    curTid = -1u;
    executorTid = -1u;
    executorInSyscall = false;
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
    //PIN_AddSyscallEntryFunction(SyscallEnter, 0);
    //PIN_AddSyscallExitFunction(SyscallExit, 0);
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
