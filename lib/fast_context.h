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

#ifndef CONTEXT_H_
#define CONTEXT_H_

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

// When defined, reads and writes check that tc is valid, BUT THEY CANNOT BE
// INLINED. Thus, these carry a ~5x perf penalty!!
#define CHECK_TC(tc) //assert(tc)

namespace spin {

/* Performance- and locality-optimized context state */

static REG vectorRegBase = REG_INVALID_;

struct ThreadContext {
    uint64_t rip;
    uint64_t rflags;
    uint64_t gpRegs[REG_GR_LAST - REG_GR_BASE + 1];

    // Segments. In 64 bits, only fs and gs are used (read-only), but fsBase
    // and gsBase are also needed
    uint64_t fs, fsBase, gs, gsBase;

    // SSE/AVX registers (XMM/YMM)
    // We always allocate enough space to save/restore 256-bit YMMs.  We detect
    // whether we need to actually save/restore XMMs or YMMs at runtime.
    // NOTE(dsm): I tried to use __m256 here. BAD IDEA. Pin does not give YMM
    // regs properly aligned, and the code sequences you end up with are very
    // inefficient. Accessing this array is just one MOV per 64-bit element.
    typedef std::array<uint64_t, 4> ymmReg;
    ymmReg vectorRegs[REG_YMM_LAST - REG_YMM_BASE + 1];

    // All other regs use a normal context (huge, and accessor methods are
    // slow, but should be accessed sparingly)
    CONTEXT pinCtxt;
};

/* Init interface */

inline void InitContext(const CONTEXT* ctxt, ThreadContext* tc) {
    CHECK_TC(tc);
    PIN_SaveContext(ctxt, &tc->pinCtxt);

    tc->rip = PIN_GetContextReg(ctxt, REG_RIP);
    tc->rflags = PIN_GetContextReg(ctxt, REG_RFLAGS);

    for (uint32_t i = REG_GR_BASE; i <= REG_GR_LAST; i++) {
        tc->gpRegs[i - REG_GR_BASE] = PIN_GetContextReg(ctxt, (REG)i);
    }

    tc->fs = PIN_GetContextReg(ctxt, REG_SEG_FS);
    tc->fsBase = PIN_GetContextReg(ctxt, REG_SEG_FS_BASE);
    tc->gs = PIN_GetContextReg(ctxt, REG_SEG_GS);
    tc->gsBase = PIN_GetContextReg(ctxt, REG_SEG_GS_BASE);

    uint32_t vectorRegSize;
    if (PIN_ContextContainsState((CONTEXT*)ctxt, PROCESSOR_STATE_YMM)) {
        vectorRegSize = 32;
        vectorRegBase = REG_YMM_BASE;
    } else {  // We are running on a machine without AVX
        vectorRegSize = 16;
        vectorRegBase = REG_XMM_BASE;
    }
    const REG vectorRegBaseCopy = vectorRegBase;  // manual loop-invariant code motion
    for (uint32_t i = 0; i < 16; i++) {
        REG r = (REG)(vectorRegBaseCopy + i);
        assert(REG_Size(r) == vectorRegSize);
        PIN_GetContextRegval(ctxt, r, (uint8_t*)&tc->vectorRegs[i]);
    }
}

inline void UpdatePinContext(ThreadContext* tc) {
    CHECK_TC(tc);
    PIN_SetContextReg(&tc->pinCtxt, REG_RIP, tc->rip);
    PIN_SetContextReg(&tc->pinCtxt, REG_RFLAGS, tc->rflags);

    for (uint32_t i = REG_GR_BASE; i <= REG_GR_LAST; i++) {
        PIN_SetContextReg(&tc->pinCtxt, (REG)i, tc->gpRegs[i - REG_GR_BASE]);
    }

    // NOTE: No need to update segment regs, which are read-only

    const REG vectorRegBaseCopy = vectorRegBase;  // manual loop-invariant code motion
    assert(REG_valid(vectorRegBaseCopy));
    for (uint32_t i = 0; i < 16; i++) {
        REG r = (REG)(vectorRegBaseCopy + i);
        PIN_SetContextRegval(&tc->pinCtxt, r, (uint8_t*)&tc->vectorRegs[i]);
    }
}


/* Read interface */

template <REG r> inline ADDRINT ReadReg(const ThreadContext* tc);

template <> inline ADDRINT ReadReg<REG_RIP>(const ThreadContext* tc) { CHECK_TC(tc); return tc->rip; }
template <> inline ADDRINT ReadReg<REG_RFLAGS>(const ThreadContext* tc) { CHECK_TC(tc); return tc->rflags; }

template <> inline ADDRINT ReadReg<REG_SEG_FS>(const ThreadContext* tc) { CHECK_TC(tc); return tc->fs; }
template <> inline ADDRINT ReadReg<REG_SEG_GS>(const ThreadContext* tc) { CHECK_TC(tc); return tc->gs; }

// Get this: If these are inlined, Pin fails silently. So have a panic to ensure they do NOT inline
template <> inline ADDRINT ReadReg<REG_SEG_FS_BASE>(const ThreadContext* tc) { if (!tc) panic("Prevent Pin from inlining"); return tc->fsBase; }
template <> inline ADDRINT ReadReg<REG_SEG_GS_BASE>(const ThreadContext* tc) { if (!tc) panic("Prevent Pin from inlining"); return tc->gsBase; }

template <REG r> inline ADDRINT ReadReg(const ThreadContext* tc) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    if (i >= REG_GR_BASE && i <= REG_GR_LAST) {
        return tc->gpRegs[i - REG_GR_BASE];
    } else {
        assert(false);  // should not be called
        return 0ul;
    }
}

template <REG r> void ReadXMMReg(const ThreadContext* tc, PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_XMM_BASE && i <= REG_XMM_LAST, "Only valid for XMM regs");
    for (uint32_t w = 0; w < 2; w++) reg->qword[w] = tc->vectorRegs[i - REG_XMM_BASE][w];
}

template <REG r> void ReadYMMReg(const ThreadContext* tc, PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) reg->qword[w] = tc->vectorRegs[i - REG_YMM_BASE][w];
}

// Slow, Pin does not inline, invalid for the regs above
void ReadGenericReg(const ThreadContext* tc, REG r, PIN_REGISTER* val) {
    CHECK_TC(tc);
    PIN_GetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

// For x87 registers (ReadGenericReg does not work on them)
void ReadFPState(const ThreadContext* tc, CONTEXT* partialCtxt) {
    FPSTATE fpState;
    PIN_GetContextFPState(&tc->pinCtxt, &fpState);
    PIN_SetContextFPState(partialCtxt, &fpState);
}

/* Write interface */

template <REG r> inline void WriteReg(ThreadContext* tc, ADDRINT regVal);

template <> inline void WriteReg<REG_RIP>(ThreadContext* tc, ADDRINT regVal) { CHECK_TC(tc); tc->rip = regVal; }
template <> inline void WriteReg<REG_RFLAGS>(ThreadContext* tc, ADDRINT regVal) { CHECK_TC(tc); tc->rflags = regVal; }

template <REG r> inline void WriteReg(ThreadContext* tc, ADDRINT regVal) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    if (i >= REG_GR_BASE && i <= REG_GR_LAST) {
        tc->gpRegs[i - REG_GR_BASE] = regVal;
    } else {
        assert(false);  // should not be called (and -O3 will not dead-eliminate this code)
    }
}

// NOTE: No FS/GS write methods. Userspace does not write them

template <REG r> void WriteXMMReg(ThreadContext* tc, const PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_XMM_BASE && i <= REG_XMM_LAST, "Only valid for XMM regs");
    for (uint32_t w = 0; w < 2; w++) tc->vectorRegs[i - REG_XMM_BASE][w] = reg->qword[w];
}

template <REG r> void WriteYMMReg(ThreadContext* tc, const PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) tc->vectorRegs[i - REG_YMM_BASE][w] = reg->qword[w];
}

// Slow, Pin does not inline, invalid for the regs above
inline void WriteGenericReg(ThreadContext* tc, REG r, const PIN_REGISTER* val) {
    CHECK_TC(tc);
    PIN_SetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

// For x87 registers (WriteGenericReg does not work on them)
void WriteFPState(ThreadContext* tc, const CONTEXT* partialCtxt) {
    FPSTATE fpState;
    PIN_GetContextFPState(partialCtxt, &fpState);
    PIN_SetContextFPState(&tc->pinCtxt, &fpState);
}

}

#endif  // CONTEXT_H_
