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

struct ThreadContext {
    uint64_t rip;
    uint64_t rflags;
    uint64_t gpRegs[REG_GR_LAST - REG_GR_BASE + 1];
    
    // Segments. In 64 bits, only fs and gs are used (read-only), but fsBase
    // and gsBase are also needed
    uint64_t fs, fsBase, gs, gsBase;
   
    // NOTE: For SSE/SSE2/.../AVX, we ALWAYS save and restore 256 ymm (AVX)
    // registers, as EMM/XMM regs are aliased to YMM. This will not work if
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

    for (uint32_t i = REG_YMM_BASE; i <= REG_YMM_LAST; i++) {
        REG r = (REG)i;
        assert(REG_Size(r) == sizeof(__m256));
        PIN_GetContextRegval(ctxt, (REG)i, (uint8_t*)&tc->fpRegs[i - REG_YMM_BASE]);
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

    for (uint32_t i = REG_YMM_BASE; i <= REG_YMM_LAST; i++) {
        REG r = (REG)i;
        assert(REG_Size(r) == sizeof(__m256));
        PIN_SetContextRegval(&tc->pinCtxt, (REG)i, (uint8_t*)&tc->fpRegs[i - REG_YMM_BASE]);
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

template <REG r> void ReadFPReg(const ThreadContext* tc, PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) reg->qword[w] = tc->fpRegs[i - REG_YMM_BASE][w];
}

// Slow, Pin does not inline, invalid for the regs above
inline void ReadGenericReg(const ThreadContext* tc, REG r, PIN_REGISTER* val) {
    CHECK_TC(tc);
    PIN_GetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
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

template <REG r> void WriteFPReg(ThreadContext* tc, const PIN_REGISTER* reg) {
    CHECK_TC(tc);
    constexpr uint32_t i = (uint32_t)r;
    static_assert(i >= REG_YMM_BASE && i <= REG_YMM_LAST, "Only valid for YMM regs");
    for (uint32_t w = 0; w < 4; w++) tc->fpRegs[i - REG_YMM_BASE][w] = reg->qword[w];
}

// Slow, Pin does not inline, invalid for the regs above
inline void WriteGenericReg(ThreadContext* tc, REG r, const PIN_REGISTER* val) {
    CHECK_TC(tc);
    PIN_SetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

// Testing: even slower r/w variants using IARG_PARTIAL_CONTEXT
void ReadGenericRegPartialCtxt(const ThreadContext* tc, REG r, CONTEXT* partialCtxt) {
    CHECK_TC(tc);
    uint8_t rv[8192];
    PIN_GetContextRegval(&tc->pinCtxt, r, rv);
    PIN_SetContextRegval(partialCtxt, r, rv);
}

void WriteGenericRegPartialCtxt(ThreadContext* tc, REG r, const CONTEXT* partialCtxt) {
    CHECK_TC(tc);
    uint8_t rv[8192];
    PIN_GetContextRegval(partialCtxt, r, rv);
    PIN_SetContextRegval(&tc->pinCtxt, r, rv);
}

}

#endif  // CONTEXT_H_
