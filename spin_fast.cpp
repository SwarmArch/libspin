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

#include "context.h"
#include "spin.h"

namespace spin {

// Uncomment to do *expensive* context-to-register comparisons; only works on
// single-threaded code, where registers and the actual context stay in sync.
// Useful to catch bugs exhaustively in single-threaded code.
// Breaks Pin with -inline 0 (Pin tries to spill FS, craps itself)
//#define DEBUG_COMPARE_REGS

// We want to be able to have switchcalls before the first instruction of a
// basic block, which thankfully we can do at low overhead with multi-versioned
// traces. A switchcall before the first instruction of a trace starts in mode
// 0, and indirect-jumps to mode 0 so long as we're switching among threads. To
// avoid an infinite loop, the moment the switchcall returns the same thread,
// it jumps to version 1, which does not have the initial jump test. All
// version 1 traces ALWAYS immediately jump to mode 0.
#define TRACE_VERSION_DEFAULT (0)
#define TRACE_VERSION_NOJUMP  (1)


template <typename ...Args>
void info(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    printf("[spin] %s\n", buf);
}

template <typename ...Args>
void panic(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    fprintf(stderr, "[spin] Panic: %s\n", buf);
    fflush(stderr);
    exit(1);
}

// Thread context state (2Kthreads is Pin's current limit)
#define MAX_THREADS 2048
std::array<ThreadContext, MAX_THREADS> contexts;

// Scratch register assigned by Pin to hold a pointer to the current thread's
// context. Pin does register renaming, so this does not sacrifice a real
// register. Allows single-instruction functions. This is the register index,
// NOT the value of the pointer. When uncaptured, this register is nullptr.
REG tcReg;

// Scratch register used on switchcalls
REG switchReg;

// Callbacks, set on init
TraceCallback traceCallback = nullptr;
UncaptureCallback uncaptureCallback = nullptr;
ThreadCallback captureCallback = nullptr;
ThreadCallback threadStartCallback = nullptr;
ThreadCallback threadEndCallback = nullptr;

/* Tracing design: We interpose on all instrumentation (InsertCall) routines.
 * Instrumentation is done at trace granularity. We have regular and
 * exceptional traces. Exceptional traces are those that begin with a syscall
 * instruction (and, by definition, are single-instruction traces).
 *
 * On regular traces, we add the following instrumentation to preserve the
 * register context:
 *  
 *  Original:
 *    BBL1: I1
 *          I2
 *          I3
 *          BR1
 *    BBL2: I4
 *          I5
 *          JMP
 *
 *  Instrumented:
 *          TraceGuard()
 *          ReadRegs(BBL1)
 *          I1
 *          I2
 *          I3
 *          BR1 (taken_branch)-> WriteRegs(BBL1)
 *          ReadRegs(BBL2)
 *          I4
 *          I5
 *          JMP -> WriteRegs(BBL1+BBL2)
 *
 *  TraceGuard() checks tcReg is set, which only happens if this thread is the
 *  executor. Otherwise, we've returned from a syscall or just started, and the
 *  thread should be parked and wait to either take a syscall or become the
 *  executor.
 *
 *  ReadRegs() and WriteRegs() calls are inserted to read the registers right
 *  before the instructions run. Doing this at trace granularity reduces
 *  overheads vs doing this for every instruction, and is much more precise
 *  than always switching full contexts in and out.
 *
 *  CALLS:
 *
 *  The tool can add two types of calls: conventional calls that do not change
 *  the executing thread, and switchCalls that do. From the tool's perspective,
 *  there is little difference except that switchCalls must return the target
 *  thread id, and cannot be inserted before the first instruction of a trace
 *  (in other words, once the tool chooses to run a thread, it commits to
 *  running it for at least one instruction).
 *
 *  Conventional calls simply cause a break on the BBL, and all registers are
 *  saved in case the instrumentation routine reads or writes them (TODO: a
 *  potential optimization is to detect when the call requests the SPIN_CONTEXT,
 *  and only read/write regs then). For example, with a normal call between I2
 *  and I3, we'd have:
 *  
 *          TraceGuard()
 *          ReadRegs(I1+I2)
 *          I1
 *          I2
 *          WriteRegs(I1+I2)
 *          ConventionalCall()
 *          ReadRegs(I3)
 *          I3
 *          ...
 *
 * Conventional calls inserted at TAKEN_BRANCH points work similarly, though
 * we leverage the existing instrumentation:
 *          
 *         BR1 (taken_branch) -> WriteRegs(BBL1) + ConventionalCall()
 *
 * SwitchCalls always finish the trace, as they cause an indirect jump. A
 * switchcall between I2 and I3 has the following sequence:
 *
 *         TraceGuard()
 *         ReadRegs(I1+I2)
 *         I1
 *         I2
 *         WriteRegs(I1+I2)
 *         SwitchCall()
 *         SwitchHandler()
 *         jmpq %rax
 *
 * By convention (see spin.h), SwitchCall() returns the desired thread to real
 * rax (this is safe since we've written every app register).  SwitchHandler()
 * saves the current thread's rip, reads rax, verifies it's a legit thread,
 * changes tcReg to its ThreadContext, and sets rax to the new context's rip.
 *
 * SYSCALLS:
 *
 * Syscalls exist for two purposes: making the system useful and ruining our
 * day. To avoid confusing Linux, the executor can't take syscalls for other
 * threads --- the corresponding physical thread needs to take it. So, when the
 * executor thread encounters a syscall:
 *
 * 1. If it's running its own context, then it needs to defer the role of the
 * executor to another thread and take the syscall.
 * 
 * 2. If it's running another context, then it needs to defer the syscall to
 * that context, and switch to another thread.
 *
 * Because syscalls may block, the thread taking a syscall becomes uncaptured,
 * and is captured back when it returns from the syscall. These captures are
 * CONCURRENT to the executor, so that the tool may choose to block to wait on
 * a syscall if it so desires.
 *
 * Faced with the following, innocent-looking but truly evil sequence:
 *      I1
 *      I2
 *      syscall
 *
 * We do the following:
 *
 *      TraceGuard()
 *      ReadRegs(I1+I2)
 *      I1
 *      I2
 *      WriteRegs(I1+I2)
 *      SwitchToSyscall()
 *      --- Regular trace ends here ---
 *
 *      --- Syscall trace ---
 *      if (executor) <possible conventional calls from the tool>
 *      SyscallTraceGuard()
 *      ReadAllRegs()
 *      syscall
 *
 * SwitchToSycall() artificially breaks the trace using a jump so that the next
 * trace begins in a syscall.
 *
 * SyscallTraceGuard() decides where the executor should go, waking up the
 * physical thread if needed, and uncaptures the context (sets tcReg ==
 * nullptr).
 *
 * This is done to preserve the key invariant that only the right physical
 * threads run syscalls.  Unfortunately, you may have an indirect jump coming
 * from somewhere else right into the syscall instruction, so both executor and
 * non-executor threads need to be able to go through it. The executor will call
 * ExecuteAt at the guard, so it won't go through the syscall.
 *
 * EXCEPTIONS:
 *
 * Exceptions just exist to ruin everyone's day, and we don't handle them for now. TODO.
 */


/* Context read/write instrumentation */

void InsertRegReads(INS ins, IPOINT ipoint, CALL_ORDER callOrder, const std::set<REG> inRegs) {
    for (REG r : inRegs) {
        if (r == REG_RIP) continue;  // RIP must be handled differently

        AFUNPTR fp;
        bool nextClass = false;

        // Integer regs
        // NOTE: This big switch forces a full instantiation of all templates.
        // And instrumentation speed is not that critical...
#define CASE_READ_REG(reg) case reg: fp = (AFUNPTR)ReadReg<reg>; break
        switch (r) {
            CASE_READ_REG(REG_RFLAGS);
            CASE_READ_REG(REG_RAX);
            CASE_READ_REG(REG_RBX);
            CASE_READ_REG(REG_RCX);
            CASE_READ_REG(REG_RDX);
            CASE_READ_REG(REG_RDI);
            CASE_READ_REG(REG_RSI);
            CASE_READ_REG(REG_RBP);
            CASE_READ_REG(REG_RSP);
            CASE_READ_REG(REG_R8);
            CASE_READ_REG(REG_R9);
            CASE_READ_REG(REG_R10);
            CASE_READ_REG(REG_R11);
            CASE_READ_REG(REG_R12);
            CASE_READ_REG(REG_R13);
            CASE_READ_REG(REG_R14);
            CASE_READ_REG(REG_R15);
            CASE_READ_REG(REG_SEG_FS);
            CASE_READ_REG(REG_SEG_GS);
            default:
            nextClass = true;
        }
#undef CASE_READ_REG

        if (!nextClass) {
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, r, IARG_CALL_ORDER, callOrder, IARG_END);
            continue;
        }

        // FP regs
        nextClass = false;
#define CASE_READ_REG(reg) case reg: fp = (AFUNPTR)ReadFPReg<reg>; break
        switch (r) {
            CASE_READ_REG(REG_YMM0);
            CASE_READ_REG(REG_YMM1);
            CASE_READ_REG(REG_YMM2);
            CASE_READ_REG(REG_YMM3);
            CASE_READ_REG(REG_YMM4);
            CASE_READ_REG(REG_YMM5);
            CASE_READ_REG(REG_YMM6);
            CASE_READ_REG(REG_YMM7);
            CASE_READ_REG(REG_YMM8);
            CASE_READ_REG(REG_YMM9);
            CASE_READ_REG(REG_YMM10);
            CASE_READ_REG(REG_YMM11);
            CASE_READ_REG(REG_YMM12);
            CASE_READ_REG(REG_YMM13);
            CASE_READ_REG(REG_YMM14);
            CASE_READ_REG(REG_YMM15);
            default:
            nextClass = true;
        }
#undef CASE_READ_REG

        if (!nextClass) {
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
            continue;
        }

        /* X87, God save the Queen
         *
         * X87 sucks, and Pin handling of X87 sucks even more (e.g., REG_X87 is
         * a register that no APIs can access according to reg_ia32.PH, and the
         * Get/SetRegval APIs don't work for ST0-7...)
         *
         * 1. Ignore REG_X87, this seems safe
         * 2. ST0-7 ...??? If we can't pass by ref, reads we could do with
         * GetContextFPState, but stores? Do we restore the whole FP state? And
         * do that before all other reads, so that XMM reads work OK?
         * This is complete madness, might as well use ExecuteAt at that point.
         */
        if (r == REG_X87) continue;
        if (r >= REG_ST0 && r <= REG_ST7) continue;

        // Misc regs
        info("Generic RegRead %s", REG_StringShort(r).c_str());
        
        fp = (AFUNPTR)ReadGenericReg;
        INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
    }
}

void InsertRegWrites(INS ins, IPOINT ipoint, CALL_ORDER callOrder, const std::set<REG> inRegs) {
    for (REG r : inRegs) {
        if (r == REG_RIP) continue;  // RIP must be handled differently

        AFUNPTR fp;
        bool nextClass = false;

        // Integer regs
#define CASE_WRITE_REG(reg) case reg: fp = (AFUNPTR)WriteReg<reg>; break
        switch (r) {
            CASE_WRITE_REG(REG_RFLAGS);
            CASE_WRITE_REG(REG_RAX);
            CASE_WRITE_REG(REG_RBX);
            CASE_WRITE_REG(REG_RCX);
            CASE_WRITE_REG(REG_RDX);
            CASE_WRITE_REG(REG_RDI);
            CASE_WRITE_REG(REG_RSI);
            CASE_WRITE_REG(REG_RBP);
            CASE_WRITE_REG(REG_RSP);
            CASE_WRITE_REG(REG_R8);
            CASE_WRITE_REG(REG_R9);
            CASE_WRITE_REG(REG_R10);
            CASE_WRITE_REG(REG_R11);
            CASE_WRITE_REG(REG_R12);
            CASE_WRITE_REG(REG_R13);
            CASE_WRITE_REG(REG_R14);
            CASE_WRITE_REG(REG_R15);
            CASE_WRITE_REG(REG_SEG_FS);
            CASE_WRITE_REG(REG_SEG_GS);
            default:
            nextClass = true;
        }
#undef CASE_WRITE_REG

        if (!nextClass) {
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, r, IARG_CALL_ORDER, callOrder, IARG_END);
            continue;
        }

        // FP regs
        nextClass = false;
#define CASE_WRITE_REG(reg) case reg: fp = (AFUNPTR)WriteFPReg<reg>; break
        switch (r) {
            CASE_WRITE_REG(REG_YMM0);
            CASE_WRITE_REG(REG_YMM1);
            CASE_WRITE_REG(REG_YMM2);
            CASE_WRITE_REG(REG_YMM3);
            CASE_WRITE_REG(REG_YMM4);
            CASE_WRITE_REG(REG_YMM5);
            CASE_WRITE_REG(REG_YMM6);
            CASE_WRITE_REG(REG_YMM7);
            CASE_WRITE_REG(REG_YMM8);
            CASE_WRITE_REG(REG_YMM9);
            CASE_WRITE_REG(REG_YMM10);
            CASE_WRITE_REG(REG_YMM11);
            CASE_WRITE_REG(REG_YMM12);
            CASE_WRITE_REG(REG_YMM13);
            CASE_WRITE_REG(REG_YMM14);
            CASE_WRITE_REG(REG_YMM15);
            default:
            nextClass = true;
        }
#undef CASE_WRITE_REG

        if (!nextClass) {
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_CONST_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
            continue;
        }

        // Misc regs
        info("Generic RegWrite %s", REG_StringShort(r).c_str());
        
        // FIXME(dsm): See X87 comment above
        if (r == REG_X87) continue;
        if (r >= REG_ST0 && r <= REG_ST7) continue;

        fp = (AFUNPTR)WriteGenericReg;
        INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_CONST_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
    }
}

// Check you're saving the right regs...
void CompareRegs(ThreadContext* tc, const CONTEXT* ctxt) {
    auto compRegs = [=](REG r, ADDRINT tr, const char* str) {
        ADDRINT vr = PIN_GetContextReg(ctxt, r);
        if (vr != tr) {
            info("%lx: Mismatch on %s %lx != %lx (%s)", 
                    PIN_GetContextReg(ctxt, REG_RIP),
                    REG_StringShort(r).c_str(), vr, tr, str);
            assert(false);
        }
    };

    compRegs(REG_RFLAGS, tc->rflags, "flags");
    for (uint32_t i = 0; i < 16; i++) compRegs((REG)((int)REG_GR_BASE + i), tc->gpRegs[i], "gpr");
    for (uint32_t i = 0; i < REG_SEG_LAST-REG_SEG_BASE+1; i++) compRegs((REG)((int)REG_SEG_BASE + i), tc->segRegs[i], "seg");
}

ThreadContext* TraceGuard(THREADID tid, const CONTEXT* ctxt) {
    info("[%d] In TraceGuard, RIP 0x%lx ctxt 0x%lx", tid, PIN_GetContextReg(ctxt, REG_RIP), &contexts[tid]);
    if (tid) while(true) usleep(100);
    return &contexts[tid];
}

void SyscallTraceGuard() {
    info("In SyscallTraceGuard");
}

ADDRINT IsTCRegInvalid(const ThreadContext* tc) {
    return (tc == nullptr);
}

ThreadContext* SwitchHandler(ThreadContext* tc, ADDRINT nextPC, ADDRINT nextThreadId) {
    //assert(tc);
    WriteReg<REG_RIP>(tc, nextPC);
    //assert(nextThreadId < MAX_THREADS);
    //info("Switch @ 0x%lx", nextPC);
    return &contexts[nextThreadId];
}

ADDRINT GetPC(const ThreadContext* tc) {
    //info("GetPC %lx", ReadReg<REG_RIP>(tc));
    return ReadReg<REG_RIP>(tc);
}

// These are used for switchcall instrumentation
ADDRINT CheckArgsMatch(ADDRINT tc, ADDRINT sw) {
    return (tc == sw)? 1 : sw;
}

// Seems silly? Pin inlines, resulting in single-instruction register copy
ADDRINT ReturnArg(ADDRINT arg) {
    return arg;
}


void FindInOutRegs(INS ins, std::set<REG>& inRegs, std::set<REG>& outRegs) {
    for (uint32_t i = 0; i < INS_MaxNumRRegs(ins); i++) {
        REG reg = INS_RegR(ins, i);
        if (REG_valid(reg)) {
            reg = REG_FullRegName(reg);
            inRegs.insert(reg);
        }
    }

    for (uint32_t i = 0; i < INS_MaxNumWRegs(ins); i++) {
        REG reg = INS_RegW(ins, i);
        if (REG_valid(reg)) {
            reg = REG_FullRegName(reg);
            outRegs.insert(reg);
        }
    }
}

void FindInOutRegs(const std::vector<INS> idxToIns, uint32_t firstIdx, uint32_t lastIdx, std::set<REG>& inRegs, std::set<REG>& outRegs) {
    for (uint32_t idx = firstIdx; idx <= lastIdx; idx++) {
        INS ins = idxToIns[idx];  // you'd think INS_Next would work; not across BBLs!
        FindInOutRegs(ins, inRegs, outRegs);
    }
    
    // Predicated instructions, partial updates, flags registers, etc., can
    // cause no or incomplete writes. We could try to be smart and precise, but
    // for now, do the simple thing and always read the regs written
    for (REG r : outRegs) inRegs.insert(r);
    //for (REG r : inRegs) outRegs.insert(r);
}

void PrintIns(ADDRINT pc) {
    //info(" 0x%lx", pc);
}

std::string RegSetToStr(const std::set<REG> regs) {
    std::stringstream ss;
    for (REG r : regs) {
        ss << " " << REG_StringShort(r);
    }
    return ss.str();
}

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
    pt.skipLeadingSwitchCall = (TRACE_Version(trace) == TRACE_VERSION_NOJUMP);
    traceCallback(trace, pt);

    uint32_t traceInstrs = idxToIns.size();
    std::map<INS, uint32_t> insToIdx;
    for (uint32_t i = 0; i < traceInstrs; i++) insToIdx[idxToIns[i]] = i;

    // Find callpoint and switchpoint order
    struct IPoints {
        bool before;
        bool after;
        bool taken_branch;

        IPoints() : before(false), after(false), taken_branch(false) {}
    };

    IPoints callIPoints[traceInstrs];
    IPoints switchIPoints[traceInstrs];

    auto findIPoints = [&](CallpointVector cvec, IPoints* ipoints) {
        for (auto callpoint : cvec) {
            INS ins = std::get<0>(callpoint);
            IPOINT ipoint = std::get<1>(callpoint);
            uint32_t idx = insToIdx[ins];
            assert(idx < traceInstrs);
            switch (ipoint) {
                case IPOINT_BEFORE: ipoints[idx].before = true; break;
                case IPOINT_AFTER: ipoints[idx].after = true; break;
                case IPOINT_TAKEN_BRANCH: ipoints[idx].taken_branch = true; break;
                default: assert(false);
            }
        }
    };

    findIPoints(pt.callpoints, callIPoints);
    findIPoints(pt.switchpoints, switchIPoints);

    /*if (switchIPoints[0].before == true) {
        panic("Cannot set a switchpoint at the start of a basic block (IPOINT_BEFORE first instruction)");
    }*/

    // Find atomic instruction sequences (just looking at before/after points;
    // we handle taken branches differently)
    std::vector< std::tuple<uint32_t, uint32_t> > insSeqs;
    uint32_t curStart = 0;
    uint32_t curEnd = 0;
    while (true) {
        if (curEnd == traceInstrs-1) {
            insSeqs.push_back(std::tie(curStart, curEnd));
            break;
        }
        bool hasSwitch = switchIPoints[curEnd].after || switchIPoints[curEnd+1].before;
        bool closeSeq = callIPoints[curEnd].after || callIPoints[curEnd+1].before || hasSwitch ||
            INS_IsSyscall(idxToIns[curEnd]) || INS_IsSyscall(idxToIns[curEnd+1]) ||
            INS_Stutters(idxToIns[curEnd]) || INS_Stutters(idxToIns[curEnd+1]);

        if (closeSeq) {
            insSeqs.push_back(std::tie(curStart, curEnd));
            curStart = curEnd + 1;
        }

        // Comment to instrument whole traces (wasteful if switches are actually taken)
        //if (hasSwitch) break;
     
        curEnd++;
    }

#if 1
    info("trace ver %d", TRACE_Version(trace));
    for (auto seq : insSeqs) {
        uint32_t firstIdx = std::get<0>(seq);
        uint32_t lastIdx = std::get<1>(seq);
        std::set<REG> inRegs, outRegs;
        FindInOutRegs(idxToIns, firstIdx, lastIdx, inRegs, outRegs);
        info(" seq: %d-%d in:%s out:%s", firstIdx, lastIdx, RegSetToStr(inRegs).c_str(), RegSetToStr(outRegs).c_str());
    }
    uint32_t maxInstr = std::get<1>(insSeqs[insSeqs.size()-1]);
    for (uint32_t idx = 0; idx < traceInstrs; idx++) {
        INS ins = idxToIns[idx];
        const char* seqStr = "|";
        for (auto seq: insSeqs) {
            if (idx > maxInstr) seqStr = "X";
            else if (std::get<0>(seq) == idx && std::get<1>(seq) == idx) seqStr = "*";
            else if (std::get<0>(seq) == idx) seqStr = "/";
            else if (std::get<1>(seq) == idx) seqStr = "\\";
        }
        info("  %3d: 0x%lx %s %s", idx, INS_Address(ins), seqStr, INS_Disassemble(ins).c_str());
    }
#endif

    // Insert the guard, predicated to reduce overheads (as it takes the context!)
    if (TRACE_Version(trace) == TRACE_VERSION_DEFAULT) {
        INS_InsertIfCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)IsTCRegInvalid, IARG_REG_VALUE, tcReg,
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
        INS_InsertThenCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)TraceGuard,
                IARG_THREAD_ID, IARG_CONST_CONTEXT, IARG_RETURN_REGS, tcReg,
                IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
    }

    // Insert reads and writes around instruction sequences
    // Reads: Last thing before first instr in sequence
    // Writes: First thing after last instr in sequence, and after taken branches
    for (auto seq : insSeqs) {
        uint32_t firstIdx = std::get<0>(seq);
        uint32_t lastIdx = std::get<1>(seq);

        std::set<REG> inRegs, outRegs;
        FindInOutRegs(idxToIns, firstIdx, lastIdx, inRegs, outRegs);
        InsertRegReads(idxToIns[firstIdx], IPOINT_BEFORE, CALL_ORDER_LAST, inRegs);
        if (INS_HasFallThrough(idxToIns[lastIdx])) {
            InsertRegWrites(idxToIns[lastIdx], IPOINT_AFTER, CALL_ORDER_FIRST, outRegs);
#ifdef DEBUG_COMPARE_REGS
            // Do *expensive* context-to-register comparisons; only works on single-threaded code, where registers stay in sync
            INS_InsertCall(idxToIns[lastIdx], IPOINT_AFTER, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
#endif
        }

        // Write out partial regsets on taken branches
        for (uint32_t idx = firstIdx; idx <= lastIdx; idx++) {
            if (INS_IsBranchOrCall(idxToIns[idx]) || INS_IsRet(idxToIns[idx])) {
                std::set<REG> inRegs, outRegs;
                FindInOutRegs(idxToIns, firstIdx, idx, inRegs, outRegs);
                InsertRegWrites(idxToIns[idx], IPOINT_TAKEN_BRANCH, CALL_ORDER_FIRST, outRegs);
#ifdef DEBUG_COMPARE_REGS
                INS_InsertCall(idxToIns[idx], IPOINT_TAKEN_BRANCH, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
#endif
            }
        }
    }
    
    // Insert switchpoint handlers
    auto insertSwitchHandler = [&](uint32_t idx, IPOINT ipoint) {
        /* NOTE: Only IPOINT_BEFORE works for now:
         *
         * - To get IPOINT_AFTER to run, SwitchHandler needs the fallthrough
         *   address; but even then the main problem is the indirect jump is
         *   inserted out of order with IPOINT_AFTER. IndirectJump does not
         *   carry a call order, and the standard solution from other pintools
         *   seems to be to insert it before the next instruction, or after the
         *   next instruction and then delete the instruction :). We could do
         *   this in fact... if we ever need IPOINT_AFTER.
         *
         * - IPOINT_TAKEN_BRANCH does. not. work. You can't inject an indirect
         *   branch and can't change REG_RIP between traces (wouldn't that be
         *   nice). If we need it, we can define a new trace version that
         *   simply starts with an indirect branch, so that we simply delay the
         *   jump to the next instruction. This would pollute the code cache
         *   quite a bit, but should work.
         */
        if (ipoint != IPOINT_BEFORE) panic("Switchcalls only support IPOINT_BEFORE for now (can be fixed)");
        // FIXME: It seems that, to enforce a consistent set of checks, we
        // should do the 0->1 jump all the time, not just at the start of the
        // BBL. This way, we consistently run switchcalls once per successful
        // enqueue.
        /*if (idx > 0) {
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)SwitchHandler, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, REG_RIP, IARG_REG_VALUE, switchReg, IARG_RETURN_REGS, tcReg, IARG_END);
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)GetPC, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, switchReg, IARG_END);
            INS_InsertIndirectJump(idxToIns[idx], ipoint, switchReg);
        } else*/ if (TRACE_Version(trace) == TRACE_VERSION_DEFAULT) {
            // Save new tc to switchReg
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)SwitchHandler, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, REG_RIP, IARG_REG_VALUE, switchReg, IARG_RETURN_REGS, switchReg, IARG_END);
            
            // Compare, return 1 on switchReg if they match (ie if we're not switching threads), otherwise leave switchReg untouched
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)CheckArgsMatch, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, switchReg, IARG_RETURN_REGS, switchReg, IARG_END);

            // Switch to version 1 if switchReg == 1 (note this overload of switchReg is OK because no valid tc address will be 1-aligned
            INS_InsertVersionCase(idxToIns[idx], switchReg, 1, TRACE_VERSION_NOJUMP, IARG_END);

            // Otherwise, test failed, actually write tcReg and do the jump
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)ReturnArg, IARG_REG_VALUE, switchReg, IARG_RETURN_REGS, tcReg, IARG_END);
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)/*GetPC*/ReadReg<REG_RIP>, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, switchReg, IARG_END);
            INS_InsertIndirectJump(idxToIns[idx], ipoint, switchReg);
        } else {
            assert(TRACE_Version(trace) == TRACE_VERSION_NOJUMP);
            // Immediately go back to version 0
            for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
                BBL_SetTargetVersion(bbl, TRACE_VERSION_DEFAULT);
            }

            // ... and that's it. This'll just run the first instruction without the switchcall
        }
    };
    
    for (uint32_t idx = 0; idx < traceInstrs; idx++) {
        // Evaluation order matters here: If there are swtichpoints in taken
        // and fallthrough paths, we want to handle both
        if (switchIPoints[idx].before) {
            insertSwitchHandler(idx, IPOINT_BEFORE);
            break;
        }

        if (switchIPoints[idx].taken_branch) {
            insertSwitchHandler(idx, IPOINT_TAKEN_BRANCH);
        }

        if (switchIPoints[idx].after) {
            insertSwitchHandler(idx, IPOINT_AFTER);
            break;
        }
    }
    
    /*for (uint32_t idx = 0; idx < traceInstrs; idx++) {
        INS_InsertCall(idxToIns[idx], IPOINT_BEFORE, (AFUNPTR)PrintIns, IARG_ADDRINT, INS_Address(idxToIns[idx]), IARG_END);
    }*/

    // TODO: Syscall breakup code. 
}

void SyscallEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //panic("syscall!");
    ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    assert(tc);
    CopyToPinContext(tc, ctxt);
    PIN_SetContextReg(ctxt, tcReg, (ADDRINT)tc);  // FIXME: Avoid spurious guards
}

void SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //info("syscall exit");
    // dsm: The syscall might have changed ANYTHING. Do a full context write.
    /*ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    assert(tc);*/
    ThreadContext* tc = &contexts[tid];
    InitContext(tc, ctxt);
}

ThreadContext* Capture(THREADID tid, CONTEXT* ctxt) {
    ThreadContext* tc = &contexts[tid];
    assert(tc->state == ThreadContext::UNCAPTURED);
    assert(PIN_GetContextReg(ctxt, tcReg) == (ADDRINT)nullptr);

    InitContext(tc, ctxt);
    PIN_SetContextReg(ctxt, tcReg, (ADDRINT)tc);
    tc->state = ThreadContext::IDLE;
    __sync_synchronize();

    assert(false);
    // Let tool know this thread can now be used
    //captureCallback(tid);

    // Become executor or wait till uncaptured
    //captureMutex.lock();
#if 0
    if (executorTid == -1) {
        captureMutex.unlock();
    } else {
        captureMutex.unlock();
        tc->waitMutex.lock();
        if (tc->state == ThreadContext::UNCAPTURED) {
        
        }
    }
#endif
}


void ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    info("Thread %d started", tid);
    ThreadContext* tc = &contexts[tid];
    PIN_SetContextReg(ctxt, tcReg, /*(ADDRINT)tc*/(ADDRINT)nullptr);
    InitContext(tc, ctxt);

    // HACK (dsm): For whatever reason, Pin does not seem to be fully
    // transparent at the start of the program, and rflags goes askew on bit 1
    // (which is reserved?). This ensures we don't panic when doing
    // register checks.
    tc->rflags = 0x202;

    threadStartCallback(tid);
}

void ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    info("Thread %d finished", tid);
    assert(contexts[tid].state == ThreadContext::UNCAPTURED);
    threadEndCallback(tid);
}

/* Public interface */

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, ThreadCallback captureCb, UncaptureCallback uncaptureCb) {
    traceCallback = traceCb;
    threadStartCallback = startCb;
    threadEndCallback = endCb;
    captureCallback = captureCb;
    uncaptureCallback = uncaptureCb;
    
    tcReg = PIN_ClaimToolRegister();
    switchReg = PIN_ClaimToolRegister();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddSyscallEntryFunction(SyscallEnter, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
}

uint64_t getReg(const ThreadContext* tc, REG reg) {
    assert(tc);
    reg = REG_FullRegName(reg);
    if (reg == REG_RIP) return tc->rip;
    if (reg == REG_RFLAGS) return tc->rflags;
    uint32_t regIdx = (uint32_t)reg;
    if (regIdx >= REG_GR_BASE && regIdx <= REG_GR_LAST) return tc->gpRegs[regIdx - REG_GR_BASE];
    if (regIdx >= REG_SEG_BASE && regIdx <= REG_SEG_LAST) return tc->gpRegs[regIdx - REG_SEG_BASE];
    // NOTE: It's possible to support extra regs if you need them, but I don't
    // want to get into >64-bit regs and I don't think we'll ever need them
    panic("getReg(): Register %s (%d) not supported for now (edit me!)",
             REG_StringShort(reg).c_str(), regIdx);
    return -1l;
}

void setReg(ThreadContext* tc, REG reg, uint64_t val) {
    assert(tc);
    reg = REG_FullRegName(reg);
    uint32_t regIdx = (uint32_t)reg;
    if (reg == REG_RIP) {
        tc->rip = val;
    } else if (reg == REG_RFLAGS) {
        tc->rflags = val;
    } else if (regIdx >= REG_GR_BASE && regIdx <= REG_GR_LAST) {
        tc->gpRegs[regIdx - REG_GR_BASE] = val;
    } else if (regIdx >= REG_SEG_BASE && regIdx <= REG_SEG_LAST) {
        tc->gpRegs[regIdx - REG_SEG_BASE] = val;
    } else {
        panic("setReg(): Register %s (%d) not supported for now (edit me!)",
                REG_StringShort(reg).c_str(), regIdx);
    }
}

REG __getContextReg() {
    assert(traceCallback);  // o/w not initialized
    return tcReg;
}

REG __getSwitchReg() {
    assert(traceCallback);  // o/w not initialized
    return switchReg;
}

void blockAfterSwitch() {
    panic("Unimplemented");
}

void blockIdleThread(ThreadId tid) {
    panic("Unimplemented");
}

void unblock(ThreadId tid) {
    panic("Unimplemented");
}

}  // namespace spin