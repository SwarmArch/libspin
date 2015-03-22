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

#ifdef SPIN_SLOW
#error "You must compile this file without SPIN_SLOW"
#endif

#include "fast_context.h"

/* Tracing design in fast-mode SPIN: We interpose on all instrumentation
 * (InsertCall) routines. Instrumentation is done at trace granularity. We have
 * regular and exceptional traces. Exceptional traces are those that begin with
 * a syscall instruction (and, by definition, are single-instruction traces).
 *
 * NOTE(dsm): Description below is slightly outdated. Update, but in the
 * interim, read the code.
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
 * By convention (see spin.h), SwitchCall() returns the desired thread to
 * switchReg. SwitchHandler()  saves the current thread's rip, reads switchReg,
 * verifies it's a legit thread,  changes tcReg to its ThreadContext, and sets
 * switchReg to the new context's rip.
 *
 * SYSCALLS (FIXME: this should be in spin.cpp)
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

/* Thread context state */
std::array<ThreadContext, MAX_THREADS> contexts;

uint64_t GetContextTid(const ThreadContext* tc) {
    return tc - &contexts[0];
}

ThreadContext* GetTC(ThreadId tid) {
    assert(tid < MAX_THREADS);
    return &contexts[tid];
}

CONTEXT* GetPinCtxt(ThreadContext* tc) {
    return &tc->pinCtxt;
}

// FIXME: Interface is kludgy; single-caller, cleaner to specialize spin.cpp
void CoalesceContext(const CONTEXT* ctxt, ThreadContext* tc) {
    // RIP is the only valid ctxt reg that is out of date in tc
    setReg(tc, REG_RIP, PIN_GetContextReg(ctxt, REG_RIP));
    UpdatePinContext(tc);
}

/* Public context functions */
uint64_t getReg(const ThreadContext* tc, REG reg) {
    assert(tc);
    reg = REG_FullRegName(reg);
    uint32_t regIdx = (uint32_t)reg;
    if (regIdx >= REG_GR_BASE && regIdx <= REG_GR_LAST) return tc->gpRegs[regIdx - REG_GR_BASE];
    
    switch (reg) {
        case REG_RIP: return tc->rip;
        case REG_RFLAGS: return tc->rflags;
        case REG_SEG_FS: return tc->fs;
        case REG_SEG_FS_BASE: return tc->fsBase;
        case REG_SEG_GS: return tc->gs;
        case REG_SEG_GS_BASE: return tc->gsBase;
        default:
            // NOTE: It's possible to support extra regs if you need them, but I don't
            // want to get into >64-bit regs and I don't think we'll ever need them
            panic("getReg(): Register %s (%d) not supported for now (edit me!)",
                REG_StringShort(reg).c_str(), regIdx);
    }
    return -1l;  // unreachable
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
    } else {
        panic("setReg(): Register %s (%d) not supported for now (edit me!)",
                REG_StringShort(reg).c_str(), regIdx);
    }
}

ADDRINT executeAtPC = 0ul;

void executeAt(ThreadContext* tc, ADDRINT nextPC) {
#if 0 
    // This is correct but unnecessary, as users of executeAt must return
    setReg(tc, REG_RIP, nextPC);
    UpdatePinContext(tc);
    CONTEXT* pinCtxt = GetPinCtxt(tc);
    PIN_SetContextReg(pinCtxt, tcReg, (ADDRINT)tc);
    PIN_SetContextReg(pinCtxt, tidReg, GetContextTid(tc));
    PIN_ExecuteAt(GetPinCtxt(tc));
#else
    // Instead, just record the PC and check it in SwitchHandler
    assert(!executeAtPC);
    executeAtPC = nextPC;
    DEBUG("executeAtPC set %lx (tid %d)", executeAtPC, GetContextTid(tc));
#endif
}


/* Instrumentation */

void X87Panic(ADDRINT pc) {
    panic("x87 instruction at PC 0x%lx. We do not handle x87. Recompile with -mno-80387 or use spin_slow.", pc);
}

/* Context read/write instrumentation */

void InsertRegReads(INS ins, IPOINT ipoint, CALL_ORDER callOrder, const std::set<REG>& inRegs) {
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
            CASE_READ_REG(REG_SEG_FS_BASE);
            CASE_READ_REG(REG_SEG_GS);
            CASE_READ_REG(REG_SEG_GS_BASE);
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

        /* X87 sucks, and Pin handling of X87 sucks even more (e.g., REG_X87 is
         * a register that no APIs can access according to reg_ia32.PH, and the
         * Get/SetRegval APIs don't work for ST0-7...)
         *
         * 1. Ignore REG_X87, this seems safe
         * 2. ST0-7 ...??? If we can't pass by ref, reads we could do with
         * GetContextFPState, but stores? Do we restore the whole FP state? And
         * do that before all other reads, so that XMM reads work OK?
         * 
         * This is complete madness, might as well use ExecuteAt at that point.
         */
        if (r == REG_X87) continue;
        if (r >= REG_ST0 && r <= REG_ST7) {
            INS_InsertCall(ins, ipoint, (AFUNPTR)X87Panic, IARG_INST_PTR, IARG_END);
            continue;
        }

        // Misc regs
        info("Generic RegRead %s", REG_StringShort(r).c_str());
        
        //fp = (AFUNPTR)ReadGenericReg;
        //INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
    }
}

void InsertRegWrites(INS ins, IPOINT ipoint, CALL_ORDER callOrder, const std::set<REG>& inRegs) {
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

        // NOTE(dsm): See X87 comment above
        if (r == REG_X87) continue;
        if (r >= REG_ST0 && r <= REG_ST7) {
            INS_InsertCall(ins, ipoint, (AFUNPTR)X87Panic, IARG_INST_PTR, IARG_END);
            continue;
        }

        if (r == REG_SEG_FS || r == REG_SEG_FS_BASE || r == REG_SEG_GS || r == REG_SEG_GS_BASE) {
            panic("Only supervisor instrs can write segment reg %s", REG_StringShort(r).c_str());
        }

        // Misc regs
        info("Generic RegWrite %s", REG_StringShort(r).c_str());

        //fp = (AFUNPTR)WriteGenericReg;
        //INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_CONST_REFERENCE, r, IARG_CALL_ORDER, callOrder, IARG_END);
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
}

uint64_t SwitchHandler(THREADID tid, PIN_REGISTER* tcRegRef, ADDRINT nextPC, uint64_t nextTid) {
    ThreadContext* tc = (ThreadContext*)tcRegRef->qword[0];
    assert(tc);
    uint32_t curTid = GetContextTid(tc);
    if (executeAtPC) {
        DEBUG("[%d] executeAtPC %lx (instead of %lx) nextTid %d", tid, executeAtPC, nextPC, nextTid);
        assert(nextTid == curTid);
        WriteReg<REG_RIP>(tc, executeAtPC);
        executeAtPC = 0;
        return 0;  // switch (we've changed the PC)
    } else {
        WriteReg<REG_RIP>(tc, nextPC);
    }
    
    if (NeedsSwitch(nextTid)) {
        RecordSwitch(tid, tc, nextTid);
    }
    
    assert(nextTid < MAX_THREADS);
    DEBUG_SWITCH("Switch @ 0x%lx tc %lx (%ld -> %ld)", nextPC, (uintptr_t)tc, tc - &contexts[0], nextTid);

    // Update tc
    if (nextTid != curTid) {
        tcRegRef->qword[0] = (ADDRINT)GetTC(nextTid);
        return 0;  // switch
    } else {
        return 1;  // no switch
    }
}

void FindInOutRegs(INS ins, std::set<REG>& inRegs, std::set<REG>& outRegs) {
    for (uint32_t i = 0; i < INS_MaxNumRRegs(ins); i++) {
        REG reg = INS_RegR(ins, i);
        if (REG_valid(reg)) {
            reg = REG_FullRegName(reg);
            inRegs.insert(reg);
        }
    }

    // FS/GS-relative accs need the base regs as well, but Pin does not flag them
    if (inRegs.count(REG_SEG_FS)) inRegs.insert(REG_SEG_FS_BASE);
    if (inRegs.count(REG_SEG_GS)) inRegs.insert(REG_SEG_GS_BASE);

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
}

std::string RegSetToStr(const std::set<REG> regs) {
    std::stringstream ss;
    for (REG r : regs) {
        ss << " " << REG_StringShort(r);
    }
    return ss.str();
}

void Instrument(TRACE trace, const TraceInfo& pt) {
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

    // If the first instruction is a syscall, DO ABSOLUTELY NOTHING.
    // The syscall guard sets the right full context for the syscall, and the
    // trace guard that runs immediately after refreshes the threadContext.
    // This trace will only run the syscall instruction.
    if (INS_IsSyscall(idxToIns[0])) return;

    // Find callpoint and switchpoint order
    
    struct IPoints {
        typedef std::vector<std::function<void()> > IPVec;
        IPVec before;
        IPVec after;
        IPVec taken_branch;

        IPoints() {}
    };

    IPoints callIPoints[traceInstrs];
    IPoints switchIPoints[traceInstrs];

    auto findIPoints = [&](CallpointVector cvec, IPoints* ipoints) {
        for (auto callpoint : cvec) {
            INS ins = std::get<0>(callpoint);
            IPOINT ipoint = std::get<1>(callpoint);
            auto ifun = std::get<2>(callpoint);
            uint32_t idx = insToIdx[ins];
            assert(idx < traceInstrs);
            switch (ipoint) {
                case IPOINT_BEFORE: ipoints[idx].before.push_back(ifun); break;
                case IPOINT_AFTER: ipoints[idx].after.push_back(ifun); break;
                case IPOINT_TAKEN_BRANCH: ipoints[idx].taken_branch.push_back(ifun); break;
                default: assert(false);
            }
        }
    };

    findIPoints(pt.callpoints, callIPoints);
    findIPoints(pt.switchpoints, switchIPoints);

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
        bool hasSwitch = switchIPoints[curEnd].after.size() || switchIPoints[curEnd+1].before.size();
        bool closeSeq = callIPoints[curEnd].after.size() || callIPoints[curEnd+1].before.size() || hasSwitch ||
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

    // Uncomment to print BBL disassembly and per-instruction info
#if 0
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

        char evStr[5];
        evStr[4] = '\0';
        evStr[3] = INS_HasFallThrough(ins)? 'f' : ' ';
        evStr[2] = (INS_IsBranchOrCall(idxToIns[idx]) || INS_IsRet(idxToIns[idx]))? 'b' : ' ';
        evStr[1] = INS_IsSyscall(idxToIns[idx])? 's' : ' ';
        evStr[0] = ' ';
        info("  %3d: 0x%lx %s %s %s", idx, INS_Address(ins), evStr, seqStr, INS_Disassemble(ins).c_str());
    }
#endif

    // Insert reads and writes around instruction sequences
    // Reads: Last thing before first instr in sequence
    // Writes: First thing after last instr in sequence, and after taken branches
    for (auto seq : insSeqs) {
        uint32_t firstIdx = std::get<0>(seq);
        uint32_t lastIdx = std::get<1>(seq);

        std::set<REG> inRegs, outRegs;
        FindInOutRegs(idxToIns, firstIdx, lastIdx, inRegs, outRegs);
        
        // TODO: Remove if we're sure we don't need these anymore
        inRegs.insert(REG_SEG_FS_BASE);
        inRegs.insert(REG_SEG_FS);

        InsertRegReads(idxToIns[firstIdx], IPOINT_BEFORE, CALL_ORDER_DEFAULT, inRegs);
        if (INS_HasFallThrough(idxToIns[lastIdx])) {
            InsertRegWrites(idxToIns[lastIdx], IPOINT_AFTER, CALL_ORDER_FIRST, outRegs);
#ifdef DEBUG_COMPARE_REGS
            // Do *expensive* context-to-register comparisons; only works on single-threaded code, where registers stay in sync
            INS_InsertCall(idxToIns[lastIdx], IPOINT_AFTER, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST+1, IARG_END);
#endif
        }

        // Write out partial regsets on taken branches
        for (uint32_t idx = firstIdx; idx <= lastIdx; idx++) {
            if (INS_IsBranchOrCall(idxToIns[idx]) || INS_IsRet(idxToIns[idx])) {
                std::set<REG> inRegs, outRegs;
                FindInOutRegs(idxToIns, firstIdx, idx, inRegs, outRegs);
                InsertRegWrites(idxToIns[idx], IPOINT_TAKEN_BRANCH, CALL_ORDER_FIRST, outRegs);
#ifdef DEBUG_COMPARE_REGS
                INS_InsertCall(idxToIns[idx], IPOINT_TAKEN_BRANCH, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_CALL_ORDER, CALL_ORDER_FIRST+1, IARG_END);
#endif
            }
        }
    }

    /* Insert switchcalls, switch handlers, and normal calls
     *
     * NOTE: For switchcalls, only IPOINT_BEFORE works for now:
     *
     * - To get IPOINT_AFTER to run, SwitchHandler needs the fallthrough
     *   address; but even then the main problem is the indirect jump is
     *   inserted out of order with IPOINT_AFTER. IndirectJump does not carry a
     *   call order, and the standard solution from other pintools seems to be
     *   to insert it before the next instruction, or after the next
     *   instruction and then delete the instruction :). We could do this in
     *   fact... if we ever need IPOINT_AFTER.
     *
     * - IPOINT_TAKEN_BRANCH does. not. work. You can't inject an indirect
     *   branch and can't change REG_RIP between traces (wouldn't that be
     *   nice). If we need it, we can define a new trace version that simply
     *   starts with an indirect branch, so that we simply delay the jump to
     *   the next instruction. This would pollute the code cache quite a bit,
     *   but should work.
     *
     * To support switchcalls at arbitrary points, we produce 2 trace versions:
     * DEFAULT and NOJUMP. NOJUMP traces have no switchcall at the befinning of
     * the trace, and therefore no indirect jump. Otherwise, both versions
     * follow the same sequence: SwitchHandler returns the new tc, and if it's
     * the same, we switch to version NOJUMP, otherwise, we go through the
     * indirect jump. This achieves the intended effect of not calling the
     * switchcall again after it returns the same tid.
     */
    for (uint32_t idx = 0; idx < traceInstrs; idx++) {
        // 1. Switchcalls
        if (switchIPoints[idx].after.size()) panic("Switchcalls at IPOINT_AFTER not supported");
        if (switchIPoints[idx].taken_branch.size()) panic("Switchcalls at IPOINT_TAKEN_BRANCH not supported");
        if (switchIPoints[idx].before.size() > 1) panic("Multiple switchcalls per IPOINT not supported");
        
        // Skip leading switchcall in NOJUMP version
        bool skipSwitchcall = (idx == 0 && TRACE_Version(trace) != TRACE_VERSION_DEFAULT);
        
        if (switchIPoints[idx].before.size() && !skipSwitchcall) {
            // Insert switchcall
            switchIPoints[idx].before[0]();
            IPOINT ipoint = IPOINT_BEFORE;
            
            // Save whether we should switch to switchReg
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)SwitchHandler, IARG_THREAD_ID, IARG_REG_REFERENCE, tcReg, IARG_REG_VALUE, REG_RIP, IARG_REG_VALUE, switchReg, IARG_RETURN_REGS, switchReg, IARG_END);

            // Switch to version 1 if switchReg == 1
            INS_InsertVersionCase(idxToIns[idx], switchReg, 1, TRACE_VERSION_NOJUMP, IARG_END);
            // NOTE: This won't work if 1->1 transitions just continue through the trace, but that doesn't seem to be the case.

            // Otherwise, test failed, load PC and tidReg and do the jump
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)ReadReg<REG_RIP>, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, switchReg, IARG_END);
            INS_InsertCall(idxToIns[idx], ipoint, (AFUNPTR)GetContextTid, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, tidReg, IARG_END);
            INS_InsertIndirectJump(idxToIns[idx], ipoint, switchReg);

            // Stop adding instrumentation to this trace, nothing should run after the jump
            break;
        }

        // 2. Insert normal calls
        for (auto& f : callIPoints[idx].before) f();
        for (auto& f : callIPoints[idx].after) f();
        for (auto& f : callIPoints[idx].taken_branch) f();
    }

    // NOJUMP traces must go back to version 0 by default to avoid missing
    // switchcalls th the start of the next trace
    if (TRACE_Version(trace) != TRACE_VERSION_DEFAULT) {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            BBL_SetTargetVersion(bbl, TRACE_VERSION_DEFAULT);
        }
    }
}

}  // namespace spin
