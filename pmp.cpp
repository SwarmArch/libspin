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

#include "context.h"
#include "pmp.h"

//#define info(args...)
//#define info(fmt, args...) {printf("[pmp] " fmt "\n", args);}

template <typename ...Args>
void info(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    printf("[pmp] %s\n", buf);
}

template <typename ...Args>
void panic(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    fprintf(stderr, "[pmp] Panic: %s\n", buf);
    fflush(stderr);
    exit(1);
}

namespace pmp {

// Thread context state (2Kthreads is Pin's current limit)
#define MAX_THREADS 2048
std::array<ThreadContext, MAX_THREADS> contexts;

// Scratch register assigned by Pin to hold a pointer to the current thread's
// context. Pin does register renaming, so this does not sacrifice a real
// register. Allows single-instruction functions. This is the register index,
// NOT the value of the pointer. When uncaptured, this register is nullptr.
REG tcReg;

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
 *  potential optimization is to detect when the call requests the PMP_CONTEXT,
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
 * By convention (see pmp.h), SwitchCall() returns the desired thread to real
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

        // Misc regs
        info("Generic RegRead %s", REG_StringShort(r).c_str());
        
        // FIXME (dsm): Looks like REG_X87 == touching the FP stack. Should
        // probably save and restore all ST or MM regs, or something like that.
        // JUST BAILING WILL BREAK X87 CODE
        // (but given how deprecated x87 FP is, will this really be an issue?)
        if (r == REG_X87) continue;
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

void TraceGuard() {
    info("In TraceGuard");
}

void SyscallTraceGuard() {
    info("In SyscallTraceGuard");
}

ADDRINT IsTCRegValid(const ThreadContext* tc) {
    return (tc != nullptr);
}

ThreadContext* SwitchHandler(ThreadContext* tc, ADDRINT nextPC, ADDRINT nextThreadId) {
    WriteReg<REG_RIP>(tc, nextPC);
    return &contexts[nextThreadId];
}

ADDRINT GetPC(const ThreadContext* tc) {
    return ReadReg<REG_RIP>(tc);
}

void FindInOutRegs(INS firstIns, INS lastIns, std::set<REG>& inRegs, std::set<REG>& outRegs) {
    INS ins = firstIns;
    while (true) {
        uint32_t numOperands = INS_OperandCount(ins);
        for (uint32_t op = 0; op < numOperands; op++) {
            bool read = INS_OperandRead(ins, op);
            bool write = INS_OperandWritten(ins, op);
            assert(read || write);

            // PIN is very finicky in getting registers out. This seems to
            // work; Maybe it's better to use XED directly? (as in the zsim
            // decoder)
            REG reg = INS_OperandReg(ins, op);
            if (!reg) reg = INS_OperandMemoryBaseReg(ins, op);
            if (!reg) reg = INS_OperandMemoryIndexReg(ins, op);
            if (!reg) reg = INS_OperandMemorySegmentReg(ins, op);
            if (!reg) continue;

            reg = REG_FullRegName(reg);  // eax -> rax, etc; o/w we'd miss a bunch of deps!
            if (read) inRegs.insert(reg);
            if (write) outRegs.insert(reg);
        }

        if (ins == lastIns) break;
        ins = INS_Next(ins);
        assert(INS_Valid(ins));
    }

    // FIXME rsp hack... can't get Pin to capture it reliably
    if (true || outRegs.find(REG_RSP) != outRegs.end()) {
        inRegs.insert(REG_RSP);
    }
    if (true || inRegs.find(REG_RSP) != inRegs.end()) {
        outRegs.insert(REG_RSP);
    }

    // FIXME: Are we handling predication??? If an ins is predicated, we should add all its outRegs to its inRegs!
}

void Trace(TRACE trace, VOID *v) {
    TraceInfo pt;
    traceCallback(trace, pt);
    
    // Order the trace's instructions
    std::vector<INS> idxToIns;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            idxToIns.push_back(ins);
        }
    }
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

    if (switchIPoints[0].before == true) {
        panic("Cannot set a switchpoint at the start of a basic block (IPOINT_BEFORE first instruction)");
    }

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
        bool closeSeq = callIPoints[curEnd].after || callIPoints[curEnd+1].before || hasSwitch;

        if (closeSeq) {
            insSeqs.push_back(std::tie(curStart, curEnd));
            curStart = curEnd + 1;
        }

        if (hasSwitch) break;
     
        curEnd++;
    }

    // Insert the guard, predicated to reduce overheads (as it takes the context!)
    INS_InsertIfCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)IsTCRegValid, IARG_REG_VALUE, tcReg,
            IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);
    INS_InsertThenCall(idxToIns[0], IPOINT_BEFORE, (AFUNPTR)TraceGuard, IARG_REG_VALUE, tcReg,
            IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);

    // Insert reads and writes around instruction sequences
    // Reads: Last thing before first instr in sequence
    // Writes: First thing after last instr in sequence, and after taken branches
    for (auto seq : insSeqs) {
        uint32_t firstIdx = std::get<0>(seq);
        uint32_t lastIdx = std::get<1>(seq);

        std::set<REG> inRegs, outRegs;
        FindInOutRegs(idxToIns[firstIdx], idxToIns[lastIdx], inRegs, outRegs);
        InsertRegReads(idxToIns[firstIdx], IPOINT_BEFORE, CALL_ORDER_LAST, inRegs);
        if (INS_HasFallThrough(idxToIns[lastIdx])) {
            InsertRegWrites(idxToIns[lastIdx], IPOINT_AFTER, CALL_ORDER_FIRST, outRegs);
        }

        // Write out partial regsets on taken branches
        for (uint32_t idx = firstIdx; idx <= lastIdx; idx++) {
            if (INS_IsBranchOrCall(idxToIns[idx]) || INS_IsRet(idxToIns[idx])) {
                std::set<REG> inRegs, outRegs;
                FindInOutRegs(idxToIns[firstIdx], idxToIns[idx], inRegs, outRegs);
                InsertRegWrites(idxToIns[lastIdx], IPOINT_TAKEN_BRANCH, CALL_ORDER_FIRST, outRegs);
            }
        }
    }
    
    // Insert switchpoint handlers
    auto insertSwitchHandler = [&](uint32_t idx, IPOINT ipoint) {
        assert(idx > 0 || ipoint != IPOINT_BEFORE);
        // NOTE: Do the calls and indirect jump come out in the same order? We might have to tweak the switchpoint priority
        INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)SwitchHandler, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, REG_RAX, IARG_RETURN_REGS, tcReg, IARG_END);
        INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)GetPC, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, REG_RAX, IARG_END);
        INS_InsertIndirectJump(idxToIns[idx], ipoint, REG_RAX);
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
    

    // TODO: Syscall breakup code. 
}

#if 0
    for (uint32_t i = 0; i < traceInstrs; i++) {

    }



    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        std::set<REG> inRegs, outRegs;
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            uint32_t numOperands = INS_OperandCount(ins);
            for (uint32_t op = 0; op < numOperands; op++) {
                bool read = INS_OperandRead(ins, op);
                bool write = INS_OperandWritten(ins, op);
                assert(read || write);

                // PIN is very finicky in getting registers out. This seems to workMaybe it';s better to use XED directly? (as )
                REG reg = INS_OperandReg(ins, op);
                if (!reg) reg = INS_OperandMemoryBaseReg(ins, op);
                if (!reg) reg = INS_OperandMemoryIndexReg(ins, op);
                if (!reg) reg = INS_OperandMemorySegmentReg(ins, op);
                if (!reg) continue;

                reg = REG_FullRegName(reg);  // eax -> rax, etc; o/w we'd miss a bunch of deps!
                if (read) inRegs.insert(reg);
                if (write) outRegs.insert(reg);
            }
        }

        // FIXME rsp hack... can't get Pin to capture it reliably
        if (true || outRegs.find(REG_RSP) != outRegs.end()) {
            inRegs.insert(REG_RSP);
        }
        if (true || inRegs.find(REG_RSP) != inRegs.end()) {
            outRegs.insert(REG_RSP);
        }
#if 0
        info("BBL 0x%lx ins %d", BBL_Address(bbl), BBL_NumIns(bbl));
        for (REG x : inRegs)  info("i %3d %s", x, REG_StringShort(x).c_str());
        for (REG x : outRegs) info("o %3d %s", x, REG_StringShort(x).c_str());
        info("  %s", INS_Disassemble(BBL_InsTail(bbl)).c_str());
#endif

#if 1
        INS rIns = BBL_InsHead(bbl);
        // Uncomment to always write what you read... should always work except if the reg save/restore functions are wrong
        //InsertRegWrites(rIns, IPOINT_BEFORE, inRegs);
        // Uncomment to do *expensive* context-to-register comparisons
        INS_InsertCall(rIns, IPOINT_BEFORE, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_END);
        InsertRegReads(rIns, IPOINT_BEFORE, inRegs);

        INS tIns = BBL_InsTail(bbl);
        if(!(INS_IsBranchOrCall(tIns) || INS_IsRet(tIns) || INS_IsSyscall(tIns) || INS_HasFallThrough(tIns))) {
            info("FIXME unhandled control flow... %s", INS_Disassemble(tIns).c_str());
            assert(false);
        }
        if (INS_IsBranchOrCall(tIns) || INS_IsRet(tIns)) {
            InsertRegWrites(tIns, IPOINT_TAKEN_BRANCH, outRegs);
        }

        // FIXME(dsm): A syscall needs to refresh the whole context, because
        // the OS is going to see whatever's in the Pin CONTEXT* object. This
        // is crucial in PLS, but I'm guessing we'll handle syscalls
        // differently anyway...
#if 0
        if (INS_IsSyscall(tIns)) {
            InsertRegReads(tIns, IPOINT_BEFORE, ALLTHEREGS!);
        }
#endif

        // FIXME! This may overwrite valid regs if syscall modifies a reg.
        if (INS_IsSyscall(tIns)) {
            InsertRegWrites(tIns, IPOINT_BEFORE, outRegs);
        }

        if (INS_HasFallThrough(tIns)) {
            InsertRegWrites(tIns, IPOINT_AFTER, outRegs);
        }
#endif
    }

}
#endif

void SyscallEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    CopyToPinContext(tc, ctxt);
}

void SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //info("syscall exit");
    // dsm: The syscall might have changed ANYTHING. Do a full context write.
    ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
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
    PIN_SetContextReg(ctxt, tcReg, (ADDRINT)tc);
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

void init(TraceCallback traceCb, ThreadCallback startCb, ThreadCallback endCb, ThreadCallback captureCb, UncaptureCallback uncaptureCb) {
    traceCallback = traceCb;
    threadStartCallback = startCb;
    threadEndCallback = endCb;
    captureCallback = captureCb;
    uncaptureCallback = uncaptureCb;
    
    tcReg = PIN_ClaimToolRegister();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddSyscallEntryFunction(SyscallEnter, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);
}

}
