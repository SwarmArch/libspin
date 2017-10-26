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

#include "mutex.h"
#include "assert.h"
#include "spin.h"
#include "log.h"

mutex logMutex; // FIXME: To log.cpp

// Switches are very frequent... comment unless you're explicitly debugging them
#define DEBUG(args...) //info(args)
#define DEBUG_SWITCH(args...) //info(args)

// Pin's limit is 2Kthreads (as of 2.12)
#define MAX_THREADS 2048

/* State and functions common to fast and slow tracing */
namespace spin {
    REG tcReg;  // If executor, pointer to threadContext; o/w, null
    REG tidReg;  // If executor, tid of running thread
    REG switchReg;  // Used on switches

    // Tracing routines need to be predicated on NeedsSwitch (which is
    // guaranteed to inline), and must call RecordSwitch to keep the executor
    // logic in sync.
    inline uint64_t NeedsSwitch(uint64_t curTid, uint64_t nextTid) __attribute__((always_inline));
    void RecordSwitch(THREADID tid, ThreadContext* tc, uint64_t nextTid);

    // Routines used to infer whether we need to switch
    void NotifySetPC(uint32_t tid);
    void NotifySetLiveReg();  // only used in slow mode
};

/* Context state and tracing functions */
#ifdef SPIN_SLOW
#include "slow_tracing.h"
#else
#include "fast_tracing.h"
#endif

namespace spin {

enum ThreadState  {
    UNCAPTURED, // Out in a syscall or other point out of our control. Will trip a capture point when it comes back to Pin; will trip before any other instrumentation function.
    BLOCKED,    // In program code, but blocked by the tool
    IDLE,       // Runnable but not active
    RUNNING,    // Currently running
    // Transitions: start -> UNCAPTURED
    //              On capture points: UNCAPTURED -> {IDLE, RUNNING}
    //              On switchpoints: IDLE <-> RUNNING
    //              On uncapture points: RUNNING -> UNCAPTURED
    //              On block/unblock: IDLE <-> BLOCKED
};

enum SwitchFlags : uint8_t {
    SF_NONE = 0x0,
    SF_SETPC = 0x1,
    SF_BLOCK = 0x2,
    SF_LOOP = 0x4,
    SF_SETLIVEREG = 0x8,
};

// Executor state (all strictly protected by executorMutex)
std::array<ThreadState, MAX_THREADS> threadStates;
std::array<mutex, MAX_THREADS> waitLocks;
volatile uint32_t executorTid;  // volatile b/c it's speculatively checked outside of a critical section
uint32_t curTid;
uint32_t capturedThreads;
bool executorInSyscall;
uint8_t switchFlags;
// volatile b/c it's speculatively checked outside of a critical section
volatile bool inUncaptureCallback;
aligned_mutex executorMutex;

// Callbacks, set on init or separately
TraceCallback traceCallback = nullptr;
CaptureCallback captureCallback = nullptr;
UncaptureCallback uncaptureCallback = nullptr;
ThreadCallback threadStartCallback = nullptr;
ThreadCallback threadEndCallback = nullptr;
SyscallCallback syscallEnterCallback = nullptr;
SyscallCallback syscallExitCallback = nullptr;

/* Helper debug method */
void PrintContext(uint32_t tid, const char* desc, const CONTEXT* ctxt) {
    auto r = [&](REG reg) -> void* {
        return (void*)PIN_GetContextReg(ctxt, reg);
    };
    info("[%d] %s context:", tid, desc);
    info(" rip: %18p   rflags: %18p", r(REG_RIP), r(REG_RFLAGS));
    info(" rsp: %18p      rbp: %18p", r(REG_RSP), r(REG_RBP));
    info(" rax: %18p      rbx: %18p", r(REG_RAX), r(REG_RBX));
    info(" rcx: %18p      rdx: %18p", r(REG_RCX), r(REG_RDX));
    info(" rsi: %18p      rdi: %18p", r(REG_RSI), r(REG_RDI));
    info("  r8: %18p       r9: %18p", r(REG_R8), r(REG_R9));
    info(" r10: %18p      r11: %18p", r(REG_R10), r(REG_R11));
    info(" r12: %18p      r13: %18p", r(REG_R12), r(REG_R13));
    info(" r14: %18p      r15: %18p", r(REG_R14), r(REG_R15));
}

/* Capture, uncapture, and executor handling */

void ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    executorMutex.lock();
    DEBUG("Thread %d started", tid);
    threadStartCallback(tid);
    assert(threadStates[tid] == UNCAPTURED);
    PIN_SetContextReg(ctxt, tcReg, (ADDRINT)nullptr);  // will be captured immediately
    executorMutex.unlock();
}

void ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    executorMutex.lock();
    DEBUG("Thread %d finished", tid);
    if (threadStates[tid] == RUNNING) {
        assert(capturedThreads == 1);
        // This is the last thread, nothing to do. We do not call
        // uncaptureCallback, but the tool can detect termination by seeing the
        // thread count go to 0.
        // FIXME: Race between thread creation and exit?
    } else {
        assert(threadStates[tid] == UNCAPTURED);
    }
    threadEndCallback(tid);
    executorMutex.unlock();
}

/* Tracing sequence*/

// Helper method for guards. Must be called with executorMutex held
void UncaptureAndSwitch() {
    // The callback may run code that calls spin::unblock and spin::block. For
    // example, in ordspecsim, in an effort to find a next thread, the simulator
    // could process several non-thread events, some of which affect thread
    // state, e.g. AbortTaskOnThread. If the uncaptureCallback calls
    // spin::unblock, it's safe to skip the lock, since we know it's held.
    inUncaptureCallback = true;
    uint64_t nextTid = uncaptureCallback(curTid, GetTC(curTid));
    inUncaptureCallback = false;
    if (nextTid >= MAX_THREADS) panic("Switchcall returned invalid tid %d", nextTid);
    if (threadStates[nextTid] != IDLE) {
        panic("Switchcall returned tid %d, which is not IDLE (state[%d] = %d, curTid = %d executorTid = %d)",
                nextTid, nextTid, threadStates[nextTid], curTid, executorTid);
    }

    capturedThreads--;
    assert(threadStates[curTid] == RUNNING);
    threadStates[curTid] = UNCAPTURED;
    curTid = nextTid;
    assert(threadStates[curTid] == IDLE);
    threadStates[curTid] = RUNNING;
}

// Execute specified tid, does not return
void Execute(ThreadId tid, bool isSyscall) {
    ThreadContext* tc = GetTC(tid);
    UpdatePinContext(tc);
    CONTEXT* pinCtxt = GetPinCtxt(tc);
    PIN_SetContextReg(pinCtxt, tcReg, (ADDRINT)(isSyscall? nullptr : tc));
    PIN_SetContextReg(pinCtxt, tidReg, isSyscall? -1 : tid);
    PIN_ExecuteAt(pinCtxt);
}

uint64_t RunTraceGuard(uint64_t executor) {
    return !executor;
}

// Helper, see below (also used from RecordSwitch)
void WaitForExecutorRoleOrSyscall(THREADID tid, bool alwaysBlock);

// Runs only if we're coming back from a syscall
void TraceGuard(THREADID tid, const CONTEXT* ctxt) {
    executorMutex.lock();
    assert(PIN_GetContextReg(ctxt, tcReg) == (ADDRINT)nullptr);
    DEBUG("[%d] In TraceGuard() (curTid %d rip 0x%lx er %d state %d ncap %d)", tid, curTid,
            PIN_GetContextReg(ctxt, REG_RIP), PIN_GetContextReg(ctxt, tcReg),
            threadStates[tid], capturedThreads);

    ThreadContext* tc = GetTC(tid);
    InitContext(ctxt, tc);

    // syscallExitCallback may change tc, but unlike with syscallEnter, we
    // don't need to do anything special to handle changes to the PC.
    //
    // NOTE: syscallExitCallback gets called on every syscall exit AND on
    // thread start. This is sensible (the forked/spawned thread is moving into
    // userspace after all), but it's not Pin behavior and there's not a
    // matching syscallEnter (same this as how sys_exit has an enter but not an
    // exit). Leaving as-is because API users don't care, but we could filter
    // out the first entry into userspace.
    if (syscallExitCallback) syscallExitCallback(tid, tc);

    if (threadStates[tid] == RUNNING) {
        // We did not yield executor role when we ran the syscall, so keep
        // going as usual
        assert(executorTid == tid);
        assert(curTid == tid);
        assert(capturedThreads == 1);
        executorInSyscall = false;
        DEBUG("[%d] TG: Single thread, becoming executor", tid);
        executorMutex.unlock();
        Execute(tid, false);
    }

    assert(threadStates[tid] == UNCAPTURED);
    bool runsNext = (capturedThreads == 0);

    capturedThreads++;
    threadStates[tid] = IDLE;

    captureCallback(tid, runsNext);
    // captureCallback yields our context to others. After this point, tc might have changed.

    if (runsNext) {
        DEBUG("[%d] TG: Only captured thread", tid);
        // We're the first! Make us run
        threadStates[tid] = RUNNING;
        assert(curTid == -1u);
        curTid = tid;
    }

    if (executorInSyscall) {
        DEBUG("[%d] TG: Executor is in syscall, running delayed uncapture", tid);
        assert(curTid == executorTid);
        assert(capturedThreads == 2);  // the non-uncaptured executor and us
        // Do delayed uncapture
        UncaptureAndSwitch();
        executorTid = -1u;
        executorInSyscall = false;
    }

    WaitForExecutorRoleOrSyscall(tid, false /*don't block if no executor*/);
}

// Must be called with executorLock held. Unlocks it. Never returns.
void WaitForExecutorRoleOrSyscall(THREADID tid, bool alwaysBlock) {
    // If somebody else is the executor, wait until we're woken up, either
    // because we need to run a syscall or become the executor
    while (executorTid != -1u || alwaysBlock) {
        executorMutex.unlock();
        waitLocks[tid].lock();
        executorMutex.lock();
        bool regularSyscall = (threadStates[tid] == UNCAPTURED);
        // See SyscallGuard for the delayed uncapture code
        // NOTE: Even if we were work up for a delayed syscall, an intervening
        // thread may run the delayed uncapture. That is perfectly fine.
        bool delayedUncaptureSyscall = threadStates[tid] == RUNNING &&
            executorTid == tid && executorInSyscall;
        if (regularSyscall || delayedUncaptureSyscall) {
            // Take syscall
            DEBUG("[%d] WES%d: Wakeup, taking own syscall (%s)", tid, alwaysBlock,
                    regularSyscall? "regular" : "delayed uncapture");
            executorMutex.unlock();
            Execute(tid, true);
        } else if (executorTid == -1u) {
            // NOTE: Due to wakeups interleaving with uncaptures, we can have
            // multiple threads going for the executor. For example, this
            // thread could have been woken up to claim executor, but a thread
            // that came out of a syscall got it first. Thus waking up does not
            // automatically mean executorTid == -1u, so we check.
            DEBUG("[%d] WES%d: Wakeup to claim executor", tid, alwaysBlock);
            break;
        } else {
            DEBUG("[%d] WES%d: Spurious wakeup", tid, alwaysBlock);
        }
    }

    assert(executorTid == -1u);

    // Become executor
    executorTid = tid;
    assert(curTid < MAX_THREADS);
    DEBUG("[%d] WES%d: Becoming executor, (curTid = %d, capturedThreads = %d)",
            tid, alwaysBlock, curTid, capturedThreads);
    executorMutex.unlock();
    Execute(curTid, false);
}

uint64_t RunSyscallGuard(uint64_t executor) {
    return executor;
}

void SyscallGuard(THREADID tid, const CONTEXT* ctxt) {
    executorMutex.lock();
    DEBUG("[%d] In SyscallGuard() (curTid %d rip 0x%lx er %d)", tid, curTid,
            PIN_GetContextReg(ctxt, REG_RIP), PIN_GetContextReg(ctxt, tcReg)? 1 : 0);

    assert(executorTid == tid);
    assert(curTid == PIN_GetContextReg(ctxt, tidReg));

    // Makes sure the thread's pinCtxt is updated. Depending on the tracing mode,
    // ctxt may be valid or superfluous
    CoalesceContext(ctxt, GetTC(curTid));

    if (syscallEnterCallback) {
        executorMutex.unlock();
        ThreadContext* tc = GetTC(curTid);
        // Update PC, which may be stale in ThreadContext
        uint64_t pc = getReg(tc, REG_RIP);
        syscallEnterCallback(curTid, tc);  // may change tc

        // Handle jumps
        if (getReg(tc, REG_RIP) != pc) {
            DEBUG("syscallEnterCallback changed PC 0x%lx -> %lx (curTid %d), running Execute", pc, getReg(tc, REG_RIP), curTid);
            // Treat this like a switch; checks & unsets switchFlags, etc
            RecordSwitch(tid, tc, curTid);
            Execute(curTid, false);  // does not return
            panic("??");
        }
        // FIXME(dsm): I suspect this implementation is broken in corner cases:
        // if some tc reg is changed, that will cause inconsistent switchFlags.
        // I've left a panic() below that should catch any inconsistency.
        if (switchFlags) panic("Inconsistent handling of tc writes in syscallEnterCallback()");
        executorMutex.lock();
    }

    if (curTid != tid) {
        // We need to ship off this syscall and move on to another thread
        if (capturedThreads >= 2) {
            // Both us and the tid we're running are captured and unblocked
            uint32_t wakeTid = curTid;
            UncaptureAndSwitch();  // changes curTid
            waitLocks[wakeTid].unlock();  // wake syscall taker
            DEBUG("[%d] SG: Shipping syscall to real tid %d, running %d", tid, wakeTid, curTid);
            executorMutex.unlock();
            Execute(curTid, false);
        } else {
            // There's a pretty complex corner case:
            // 1. We're executing the last captured thread
            // 2. We're blocked
            //
            // Previously, we tried to enforce that blocked threads are never
            // executors to simplify this case.  Unfortunately, that would
            // require two implementations of RecordSwitch for fast and slow
            // modes. So tough it out.
            assert(capturedThreads == 1);
            assert(threadStates[tid] == BLOCKED);

            // We can't uncapture, as there's nothing to switch to! Instead:
            // 1. Post a delayed uncapture
            executorTid = curTid;
            assert(!executorInSyscall);
            executorInSyscall = true;

            // 2. Wake the other thread (who's in WaitForExecutor, see the matching logic there)
            DEBUG("[%d] SG: Waking real tid %d to run its syscall, and blocking ourselves", tid, curTid);
            waitLocks[curTid].unlock();  // wake new executor

            // 3. Block, as we are a blocked thread
            WaitForExecutorRoleOrSyscall(tid, true /*always block*/);
        }
    } else {
        // We ourselves need to take the syscall...
        if (capturedThreads >= 2) {
            // 2. Wake up another idle thread to continue execution
            // Instead of searching for an idle non-executor thread, we
            // leverage that the thread we switch to must be captured, and make
            // that the executor as well.
            UncaptureAndSwitch();  // changes curTid
            executorTid = -1u;
            DEBUG("[%d] SG: Waking real tid %d, now running %d, and going to syscall", tid, curTid, curTid);
            waitLocks[curTid].unlock();  // wake new executor
        } else {
            // 3. We're the only captured thread, so if we uncaptured ourselves
            // the tool would run out of threads. Instead, let the first
            // captured thread do a delayed uncapture (or we'll do one)
            DEBUG("[%d] SG: Delayed uncapture", tid);
            assert(!executorInSyscall);
            executorInSyscall = true;
        }

        executorMutex.unlock();

        // Take our syscall
        Execute(tid, true);
    }
}

// Should inline, avoid conditionals. Note use of | instead of || and - instead of !=
uint64_t NeedsSwitch(uint64_t curTid, uint64_t nextTid) {
    return (nextTid - curTid) | switchFlags;
}

void RecordSwitch(THREADID tid, ThreadContext* tc, uint64_t nextTid) {
    executorMutex.lock();
    if (!tc) {
        panic("[%d] I was supposed to be the executor?? But it's %d", tid, executorTid);
    }
    if ((switchFlags & SF_BLOCK) && nextTid == curTid) {
        panic("[%d] Switchcall from thread %d called blockAfterSwitch(), but returned the same thread!", tid, curTid);
    }
    if ((switchFlags & SF_SETLIVEREG) && !(switchFlags & SF_SETPC)) {
        panic("[%d] Switchcall from thread %d called setReg() on the live context, but did not set a new PC. Unsupported in slow mode!", tid, curTid);
    }

    assert(executorTid == tid);
    assert(curTid <= MAX_THREADS);

    assert(threadStates[curTid] == RUNNING);
    threadStates[curTid] = IDLE;

    if (nextTid >= MAX_THREADS || threadStates[nextTid] != IDLE) {
        panic("[%d] Switchcall returned invalid next tid %d (state %d)", tid,
                nextTid, (nextTid < MAX_THREADS)? threadStates[nextTid] : -1);
    }

    DEBUG_SWITCH("[%d] Switching %d -> %d (%p -> %p)", tid, curTid, nextTid,
                 getReg(tc, REG_RIP), getReg(getContext(nextTid), REG_RIP));
    if (switchFlags & SF_BLOCK) {
        DEBUG("[%d] Blocking %d at switch", tid, curTid);
        threadStates[curTid] = BLOCKED;
        assert(capturedThreads > 1);
        capturedThreads--;
    }

    switchFlags = SF_NONE;
    curTid = nextTid;
    threadStates[curTid] = RUNNING;
    executorMutex.unlock();
}

void NotifySetPC(uint32_t tid) {
    if (tid == curTid) {
        DEBUG("NotifySetPC(): Changing PC of thread %d currently in switchcall", curTid);
        // NOTE: We could assert that SF_SETPC is not set, but I do not see any
        // reason to disallow multiple setReg calls in the same switchcall.
        // NOTE: Will cause a switch even if the PC is the same
        switchFlags |= SF_SETPC;
    }
}

void NotifySetLiveReg() {
    DEBUG("NotifySetLiveReg()");
    switchFlags |= SF_SETLIVEREG;
}

/* Instrumentation */

void InstrumentTrace(TRACE trace, VOID *v) {
    INS firstIns = BBL_InsHead(TRACE_BblHead(trace));
    bool isSyscallTrace = INS_IsSyscall(firstIns);

    // Trace guard
    if (!isSyscallTrace) {
        INS_InsertIfCall(firstIns, IPOINT_BEFORE, (AFUNPTR)RunTraceGuard,
                IARG_REG_VALUE, tcReg,
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertThenCall(firstIns, IPOINT_BEFORE, (AFUNPTR)TraceGuard,
                IARG_THREAD_ID, IARG_CONST_CONTEXT,
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
    }

    // Syscall guards
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsSyscall(ins)) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)RunSyscallGuard,
                        IARG_REG_VALUE, tcReg,
                        IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)SyscallGuard,
                        IARG_THREAD_ID, IARG_CONST_CONTEXT,
                        IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
            }
        }
    }

    TraceInfo pt;
    traceCallback(trace, pt);
    Instrument(trace, pt);
}

/* Public interface */

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, CaptureCallback captureCb, UncaptureCallback uncaptureCb) {
    for (auto& ts : threadStates) ts = UNCAPTURED;
    for (auto& wl : waitLocks) wl.lock();
    curTid = -1u;
    executorTid = -1u;
    executorInSyscall = false;
    switchFlags = SF_NONE;
    capturedThreads = 0;

    traceCallback = traceCb;
    threadStartCallback = startCb;
    threadEndCallback = endCb;
    captureCallback = captureCb;
    uncaptureCallback = uncaptureCb;

    tcReg = PIN_ClaimToolRegister();
    tidReg = PIN_ClaimToolRegister();
    switchReg = PIN_ClaimToolRegister();

    TRACE_AddInstrumentFunction(InstrumentTrace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
}

void setSyscallEnterCallback(SyscallCallback syscallEnterCb) {
    if (syscallEnterCallback) DEBUG("Overriding previous syscallEnterCallback");
    syscallEnterCallback = syscallEnterCb;
}

void setSyscallExitCallback(SyscallCallback syscallExitCb) {
    if (syscallExitCallback) DEBUG("Overriding previous syscallExitCallback");
    syscallExitCallback = syscallExitCb;
}

ThreadContext* getContext(ThreadId tid) {
    assert(tid < MAX_THREADS);
    assert(threadStates[tid] != UNCAPTURED);
    return GetTC(tid);
}

REG __getContextReg() {
    assert(traceCallback);  // o/w not initialized
    return tcReg;
}

REG __getSwitchReg() {
    assert(traceCallback);  // o/w not initialized
    return switchReg;
}

REG __getTidReg() {
    assert(traceCallback);  // o/w not initialized
    return tidReg;
}

void blockAfterSwitch() {
    assert(!(switchFlags & SF_BLOCK));
    switchFlags |= SF_BLOCK;  // honored by RecordSwitch
}

void blockIdleThread(ThreadId tid) {
    if (!inUncaptureCallback) executorMutex.lock();
    assert(tid < MAX_THREADS);
    assert(threadStates[tid] == IDLE);
    assert(capturedThreads > 1);
    threadStates[tid] = BLOCKED;
    capturedThreads--;
    if (!inUncaptureCallback) executorMutex.unlock();
}

void unblock(ThreadId tid) {
    if (!inUncaptureCallback) executorMutex.lock();
    assert(tid < MAX_THREADS);
    if (threadStates[tid] == BLOCKED) {
        threadStates[tid] = IDLE;
        capturedThreads++;
    } else {
        // An unblock fired right after a call to blockAfterSwitch. This makes
        // blockAfterSwitch look functionally equivalent to being blocked
        // TODO: Simplify interface: block() and unblock() for arbitrary threads!
        assert(switchFlags & SF_BLOCK);
        assert(threadStates[tid] == RUNNING);
        switchFlags &= ~SF_BLOCK;
    }
    if (!inUncaptureCallback) executorMutex.unlock();
}

void loop() {
    switchFlags |= SF_LOOP;
}

bool isLoopSet() {
    return switchFlags && SF_LOOP;
}

}  // namespace spin
