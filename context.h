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

namespace spin {

/* Performance- and locality-optimized context state */

struct ThreadContext {
    enum State  {
        UNCAPTURED, // Out in a syscall or other point out of our control. Will trip a capture point when it comes back to Pin; will trip before any other instrumentation function.
        IDLE,       // Runnable but not active
        RUNNING,    // Currently running
        // Transitions: start -> UNCAPTURED
        //              On capture points: UNCAPTURED -> {IDLE, RUNNING}
        //              On switchpoints: IDLE <-> RUNNING
        //              On uncapture points: RUNNING -> UNCAPTURED
    };
    
    State state;
    uint64_t rip;
    uint64_t rflags;
    uint64_t gpRegs[REG_GR_LAST - REG_GR_BASE + 1];
    uint64_t segRegs[REG_SEG_LAST - REG_SEG_BASE + 1];
   
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

    ThreadContext() : state(UNCAPTURED) {}
};

/* Init interface */

inline void InitContext(ThreadContext* tc, const CONTEXT* ctxt) {
    PIN_SaveContext(ctxt, &tc->pinCtxt);

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

inline void CopyToPinContext(ThreadContext* tc, CONTEXT* ctxt) {
    // First, copy our bulk pinCtxt to the Pin context
    PIN_SaveContext(&tc->pinCtxt, ctxt);
   
    // Then copy the fast regs
    PIN_SetContextReg(ctxt, REG_RIP, tc->rip);
    PIN_SetContextReg(ctxt, REG_RFLAGS, tc->rflags);

    for (uint32_t i = REG_GR_BASE; i <= REG_GR_LAST; i++) {
        PIN_SetContextReg(ctxt, (REG)i, tc->gpRegs[i - REG_GR_BASE]);
    }

    for (uint32_t i = REG_SEG_BASE; i <= REG_SEG_LAST; i++) {
        PIN_SetContextReg(ctxt, (REG)i, tc->segRegs[i - REG_SEG_BASE]);
    }

    for (uint32_t i = REG_YMM_BASE; i <= REG_YMM_LAST; i++) {
        REG r = (REG)i;
        assert(REG_Size(r) == sizeof(__m256));
        PIN_SetContextRegval(ctxt, (REG)i, (uint8_t*)&tc->fpRegs[i - REG_YMM_BASE]);
    }
}


/* Read interface */

template <REG r> inline ADDRINT ReadReg(const ThreadContext* tc);

template <> inline ADDRINT ReadReg<REG_RFLAGS>(const ThreadContext* tc) {
    return tc->rflags;
}

template <> inline ADDRINT ReadReg<REG_RIP>(const ThreadContext* tc) {
    return tc->rip;
}

template <REG r> inline ADDRINT ReadReg(const ThreadContext* tc) {
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

// Slow, Pin does not inline, invalid for the regs above
inline void ReadGenericReg(const ThreadContext* tc, REG r, PIN_REGISTER* val) {
    PIN_GetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

/* Write interface */

template <REG r> inline void WriteReg(ThreadContext* tc, ADDRINT regVal);

template <> inline void WriteReg<REG_RFLAGS>(ThreadContext* tc, ADDRINT regVal) {
    tc->rflags = regVal;
}

template <> inline void WriteReg<REG_RIP>(ThreadContext* tc, ADDRINT regVal) {
    tc->rip = regVal;
}

template <REG r> inline void WriteReg(ThreadContext* tc, ADDRINT regVal) {
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

// Slow, Pin does not inline, invalid for the regs above
inline void WriteGenericReg(ThreadContext* tc, REG r, const PIN_REGISTER* val) {
    PIN_SetContextRegval(&tc->pinCtxt, r, (uint8_t*)val);
}

}
