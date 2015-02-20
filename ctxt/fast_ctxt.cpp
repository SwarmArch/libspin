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

/* Performance- and locality-optimized context state */

struct ThreadContext {
    uint64_t tid;  // TODO: Remove if not needed
    uint64_t rip;
    uint64_t rflags;
    uint64_t gpRegs[REG_GR_LAST - REG_GR_BASE + 1];
    uint64_t segRegs[REG_SEG_LAST - REG_SEG_BASE + 1];
   
    // NOTE: For SSE/SSE2/.../AVX, we ALWAYS save and restore 256 ymm (AVX)
    // registers, as EMM/XMM regs are alieased to YMM. This will not work if
    // you try to run on < Sandy Bridge (in those archs, we should save/restore
    // XMM regs)
    // NOTE(dsm): I tried to use __m256 here. BAD IDEA. Pin does not give YMM
    // regs properly aligned, and the code sequences you end up with are very
    // inefficient. This is just 4 MOVs.
    typedef std::array<uint64_t, 4> ymmReg;
    ymmReg fpRegs[REG_YMM_LAST - REG_YMM_BASE + 1];
    
     // All other regs use a normal context (huge, and accessor methods are
     // slow, but should be accessed sparingly)
    CONTEXT pinCtxt;
};

/* Init interface */

void InitContext(ThreadContext* tc, uint32_t tid, const CONTEXT* ctxt) {
    PIN_SaveContext(ctxt, &tc->pinCtxt);
    tc->tid = tid;

    tc->rip = PIN_GetContextReg(ctxt, REG_RIP);
    tc->rflags = PIN_GetContextReg(ctxt, REG_RFLAGS);

    for (uint32_t i = REG_GR_BASE; i <= REG_GR_LAST; i++) {
        tc->gpRegs[i - REG_GR_BASE] = PIN_GetContextReg(ctxt, (REG)i);
    }

    for (uint32_t i = REG_SEG_BASE; i <= REG_SEG_LAST; i++) {
        tc->segRegs[i - REG_SEG_BASE] = PIN_GetContextReg(ctxt, (REG)i);
    }

    for (uint32_t i = REG_YMM_BASE; i <= REG_YMM_LAST; i++) {
        REG r = (REG)i;
        assert(REG_Size(r) == sizeof(__m256));
        PIN_GetContextRegval(ctxt, (REG)i, (uint8_t*)&tc->fpRegs[i - REG_YMM_BASE]);
    }
}


/* Read interface */

template <REG r> ADDRINT ReadReg(const ThreadContext* tc);

template <> ADDRINT ReadReg<REG_RFLAGS>(const ThreadContext* tc) {
    return tc->rflags;
}

template <> ADDRINT ReadReg<REG_RIP>(const ThreadContext* tc) {
    return tc->rip;
}

template <REG r> ADDRINT ReadReg(const ThreadContext* tc) {
    constexpr uint32_t i = (uint32_t)r;
    if (i >= REG_GR_BASE && i <= REG_GR_LAST) {
        return tc->gpRegs[i - REG_GR_BASE];
    } else if (i >= REG_SEG_BASE && i <= REG_SEG_LAST) {
        return tc->segRegs[i - REG_SEG_BASE];
    } else {
        assert(false);  // should not be called
        return 0ul;
    }
}

template <REG r> void ReadFPReg(const ThreadContext* tc, PIN_REGISTER* reg) {
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) reg->qword[w] = tc->fpRegs[i - REG_YMM_BASE][w];
}

// Slow, does not inline, invalid for the regs above
void ReadGenericReg(const ThreadContext* tc, REG r, PIN_REGISTER* val) {
    PIN_GetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

/* Write interface */

template <REG r> void WriteReg(ThreadContext* tc, ADDRINT regVal);

template <> void WriteReg<REG_RFLAGS>(ThreadContext* tc, ADDRINT regVal) {
    tc->rflags = regVal;
}

template <> void WriteReg<REG_RIP>(ThreadContext* tc, ADDRINT regVal) {
    tc->rip = regVal;
}

template <REG r> void WriteReg(ThreadContext* tc, ADDRINT regVal) {
    constexpr uint32_t i = (uint32_t)r;
    // NOTE: Userland does not write segment registers... but keeping for symmetry
    if (i >= REG_GR_BASE && i <= REG_GR_LAST) {
        tc->gpRegs[i - REG_GR_BASE] = regVal;
    } else if (i >= REG_SEG_BASE && i <= REG_SEG_LAST) {
        tc->segRegs[i - REG_SEG_BASE] = regVal;
    } else {
        assert(false);  // should not be called (and -O3 will not dead-eliminate this code)
    }
}

template <REG r> void WriteFPReg(ThreadContext* tc, const PIN_REGISTER* reg) {
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) tc->fpRegs[i - REG_YMM_BASE][w] = reg->qword[w];
}

// Slow, does not inline, invalid for the regs above
void WriteGenericReg(ThreadContext* tc, REG r, const PIN_REGISTER* val) {
    PIN_SetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

//#define info(args...)
#define info(args...) {printf(args); printf("\n"); }


// Scratch register assigned by Pin to hold a pointer to the current thread's
// context. Pin does register renaming. Allows single-instruction functions.
// (this is the register index, NOT the value of the pointer)
REG tcReg;

// Used as jump targets for this example, see Trace
ADDRINT jmp1, jmp2;

//uint64_t left = 500000000;
uint64_t itersLeft = 1000000000;


void JumpBack(ThreadContext* tc, PIN_REGISTER* rcx) {
    // COmpiales to a conditional...
    //ADDRINT x = (itersLeft--)? jmp1 : jmp2;
    // This is a single basic block, so Pin inlines --> faster
    uint64_t msk = -((--itersLeft) == 0); // 0 (all zeros) or -1 (all ones)
    ADDRINT x = (jmp1 & ~msk) | (jmp2 & msk);

    //info("point2 %lx %ld left %ld", x, x, left);
    rcx->qword[0] = x;
    WriteReg<REG_RCX>(tc, x);
}

void InsertRegReads(INS ins, IPOINT ipoint, const std::set<REG> inRegs) {
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
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_RETURN_REGS, r, IARG_END);
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
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_REFERENCE, r, IARG_END);
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
        INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_REFERENCE, r, IARG_END);
    }
}

void InsertRegWrites(INS ins, IPOINT ipoint, const std::set<REG> inRegs) {
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
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_VALUE, r, IARG_END);
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
            INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_REG_CONST_REFERENCE, r, IARG_END);
            continue;
        }

        // Misc regs
        info("Generic RegWrite %s", REG_StringShort(r).c_str());
        
        // FIXME(dsm): See X87 comment above
        if (r == REG_X87) continue;
        fp = (AFUNPTR)WriteGenericReg;
        INS_InsertCall(ins, ipoint, fp, IARG_REG_VALUE, tcReg, IARG_ADDRINT, r, IARG_REG_CONST_REFERENCE, r, IARG_END);
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
    // FIXME(dsm): RFLAGS check fails at the beginning of execution (Pin does
    // not capture it right), but it seems to be benign
    //compRegs(REG_RFLAGS, tc->rflags, "flags");
    for (uint32_t i = 0; i < 16; i++) compRegs((REG)((int)REG_GR_BASE + i), tc->gpRegs[i], "gpr");
    for (uint32_t i = 0; i < REG_SEG_LAST-REG_SEG_BASE+1; i++) compRegs((REG)((int)REG_SEG_BASE + i), tc->segRegs[i], "seg");
}


void SyscallExit(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    //info("syscall exit");
    // dsm: The syscall might have changed ANYTHING. Do a full context write.
    ThreadContext* tc = (ThreadContext*)PIN_GetContextReg(ctxt, tcReg);
    InitContext(tc, tc->tid, ctxt);
}

void Trace(TRACE trace, VOID *v) {
    //info("gprBase %d %s / last %d %s", REG_GR_BASE, REG_StringShort(REG_GR_BASE).c_str(), REG_GR_LAST, REG_StringShort(REG_GR_LAST).c_str());
    //info("segBase %d %s / last %d %s", REG_SEG_BASE, REG_StringShort(REG_SEG_BASE).c_str(), REG_SEG_LAST, REG_StringShort(REG_SEG_LAST).c_str());
    
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
        //INS_InsertCall(rIns, IPOINT_BEFORE, (AFUNPTR)CompareRegs, IARG_REG_VALUE, tcReg, IARG_CONST_CONTEXT, IARG_END);
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

        if (INS_HasFallThrough(tIns)) {
            InsertRegWrites(tIns, IPOINT_AFTER, outRegs);
        }
#endif
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
                // Capture address
                jmp1 = INS_Address(ins);
            }
            if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RDX && INS_OperandReg(ins, 1) == REG_RDX) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) JumpBack, IARG_REG_VALUE, tcReg, IARG_REG_REFERENCE, REG_RCX, IARG_END);
                // Need to also save the values mid-BBL...
                std::set<REG> outRegs = {REG_RSP, REG_RCX, REG_RAX};
                InsertRegWrites(ins, IPOINT_BEFORE, outRegs);
                INS_InsertIndirectJump(ins, IPOINT_BEFORE, REG_RCX);
                jmp2 = INS_Address(ins) + 3;  // xchg is 3 bytes
            }
        }
    }
}

void ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    info("Thread %d started", tid);
    ThreadContext* tc = new ThreadContext();
    PIN_SetContextReg(ctxt, tcReg, (ADDRINT)tc);
    InitContext(tc, tid, ctxt);
}


int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) info("Wrong args");

    tcReg = PIN_ClaimToolRegister();
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_StartProgram();
    return 0;
}
