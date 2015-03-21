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

#include <assert.h>
#include <deque>
#include <stdio.h>
#include <stdint.h>

#include "spin.h"

// Use libspin's mutex... hacky
#include "../lib/mutex.h"

/* Logging */

static mutex toolLogMutex;

template <typename ...Args>
static inline void info(const char* str) {
    scoped_mutex sm(toolLogMutex);
    fprintf(stdout, "[tool] %s\n", str);
    fflush(stdout);
}

template <typename ...Args>
static void info(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    info(buf);
}

/* Stats */

uint64_t insCount = 0;
uint64_t loadCount = 0;
uint64_t threadStartCount = 0;
uint64_t threadEndCount = 0;
uint64_t uncaptureCount = 0;
uint64_t switchCount = 0;

void fini(int tid, void* dummy) {
    fprintf(stderr, "Interleaver tool finished, stats:\n");
    fprintf(stderr, " instructions: %ld\n", insCount);
    fprintf(stderr, " loads: %ld\n", loadCount);
    fprintf(stderr, " threads: %ld starts, %ld ends\n", threadStartCount, threadEndCount);
    fprintf(stderr, " uncaptures: %ld\n", uncaptureCount);
    fprintf(stderr, " switches: %ld\n", switchCount);
    fprintf(stderr, " code cache size: %d bytes\n", CODECACHE_CodeMemUsed());
    fflush(stderr);
}

// Used to round-robin through threads
std::deque<uint32_t> threadQueue;
mutex queueMutex;

// Forced-switch handling due to a syscall
uint32_t uncapture(spin::ThreadId tid, spin::ThreadContext* tc) {
    scoped_mutex sm(queueMutex);
    assert(!threadQueue.empty());  // spin should not call this with a single thread
    uint32_t next = threadQueue.front();
    info("Uncapture of tid %d (pc %lx), moving to %d q{%ld elems}[%d...%d]",
            tid, spin::getReg(tc, REG_RIP), next, threadQueue.size(),
            threadQueue.front(), threadQueue.back());
    threadQueue.pop_front();
    switchCount++;
    uncaptureCount++;
    return next;
}

void capture(spin::ThreadId tid, bool runsNext) {
    info("Capturing tid %d\n", tid);
    if (!runsNext) {
        scoped_mutex sm(queueMutex);
        threadQueue.push_back(tid);
        info("Queued %d, q{%ld elems}[%d...%d]", tid, threadQueue.size(), threadQueue.front(), threadQueue.back());
    }
}

void threadStart(spin::ThreadId tid) {
    threadStartCount++;
    info("interleaver: threadStart %d", tid);
}

void threadEnd(spin::ThreadId tid) {
    threadEndCount++;
    info("interleaver: threadEnd %d", tid);
    if (threadStartCount == threadEndCount) {
        info("interleaver: done");
    }
}


void countLoad() {
    //printf("load\n");
    loadCount++;
}

bool shouldSwitch;

uint64_t countInstrsAndSwitch(spin::ThreadId curTid, const spin::ThreadContext* tc, ADDRINT curPc, uint32_t instrs, uint32_t ver, bool isTraceHead) {
    //info("switchcall, %d pc 0x%lx ver %d isTraceHead %d", curTid, curPc, ver, isTraceHead);
    uint32_t nextTid = curTid;
    if (shouldSwitch) {
        scoped_mutex sm(queueMutex);
        threadQueue.push_back(curTid);
        nextTid = threadQueue.front();
        threadQueue.pop_front();
        if (nextTid != curTid) {
            //printf("switching %d -> %d\n", curTid, nextTid);
            switchCount++;
        }
    }

    shouldSwitch = !shouldSwitch;

    // Side-effects ONLY when we return the same tid
    if (nextTid == curTid) {
        insCount += instrs;
    }
    return nextTid;
}

void trace(TRACE trace, spin::TraceInfo& pt) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryRead(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
            if (INS_HasMemoryRead2(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
        }

        //INS tgtIns = BBL_InsTail(bbl); 
        INS tgtIns = BBL_InsHead(bbl);
        //if (!INS_Stutters(tgtIns) && !INS_IsSyscall(tgtIns) && BBL_InsHead(bbl) != tgtIns) {
         pt.insertSwitchCall(tgtIns, IPOINT_BEFORE, (AFUNPTR) countInstrsAndSwitch,
                    IARG_SPIN_THREAD_ID,
                    IARG_SPIN_CONST_CONTEXT,
                    IARG_REG_VALUE, REG_RIP,
                    IARG_UINT32, BBL_NumIns(bbl),
                    IARG_UINT32, TRACE_Version(trace),
                    IARG_UINT32, tgtIns == BBL_InsHead(TRACE_BblHead(trace)));
        //}
    }
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) info("Wrong args");
    spin::init(trace, threadStart, threadEnd, capture, uncapture);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}

