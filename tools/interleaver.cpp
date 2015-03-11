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

#include "mutex.h"

uint64_t syscallCount = 0;
uint64_t insCount = 0;
uint64_t loadCount = 0;
uint64_t threadStartCount = 0;
uint64_t threadEndCount = 0;
uint64_t switchCount = 0;

void fini(int tid, void* dummy) {
    fprintf(stderr, "Interleaver tool finished, stats:\n");
    fprintf(stderr, " instructions: %ld\n", insCount);
    fprintf(stderr, " loads: %ld\n", loadCount);
    fprintf(stderr, " threads: %ld starts, %ld ends\n", threadStartCount, threadEndCount);
    fprintf(stderr, " syscalls: %ld\n", syscallCount);
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
    threadQueue.pop_front();
    printf("Uncapture of tid %d, moving to %d\n", tid, next);
    switchCount++;
    return next;
}

void capture(spin::ThreadId tid, bool runsNext) {
    printf("Capturing tid %d\n", tid);
    if (!runsNext) {
        scoped_mutex sm(queueMutex);
        threadQueue.push_back(tid);
        printf("Queued %d, q{%ld elems}[%d...%d]\n", tid, threadQueue.size(), threadQueue.front(), threadQueue.back());
    }
}

void threadStart(spin::ThreadId tid) {
    threadStartCount++;
    printf("interleaver: threadStart\n");
}

void threadEnd(spin::ThreadId tid) {
    threadEndCount++;
    printf("interleaver: threadEnd\n");
    if (threadStartCount == threadEndCount) {
        printf("interleaver: done\n");
    }
}


void countLoad() {
    //printf("load\n");
    loadCount++;
}

bool shouldSwitch;

uint32_t countInstrsAndSwitch(spin::ThreadId curTid, const spin::ThreadContext* tc, uint32_t instrs) {
    insCount += instrs;
    //printf("switchcall, %d\n", curTid);
    uint32_t next = curTid;
    if (shouldSwitch) {
        scoped_mutex sm(queueMutex);
        threadQueue.push_back(next);
        next = threadQueue.front();
        threadQueue.pop_front();
        if (next != threadQueue.back()) {
            //printf("switching to %d (%ld)\n", next, threadQueue.size());
            switchCount++;
        }
    }
    shouldSwitch = !shouldSwitch;
    return next;
}

void trace(TRACE trace, spin::TraceInfo& pt) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryRead(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
            if (INS_HasMemoryRead2(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
        }

        INS tailIns = BBL_InsTail(bbl);
#if 1
        //if (true || /*INS_HasFallThrough(tailIns) &&*/ BBL_InsHead(bbl) != tailIns /*&& !INS_Stutters(tailIns)*/) {
        if (!INS_Stutters(tailIns)) {
         pt.insertSwitchCall(tailIns, IPOINT_BEFORE, (AFUNPTR) countInstrsAndSwitch,
                    IARG_SPIN_THREAD_ID, IARG_SPIN_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }
#endif
        /*
        if (INS_IsBranchOrCall(tailIns) || INS_IsRet(tailIns)) {
            pt.insertSwitchCall(tailIns, IPOINT_TAKEN_BRANCH, (AFUNPTR) countInstrsAndSwitch,
                    IARG_SPIN_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }

        pt.insertSwitchCall(tailIns, IPOINT_BEFORE, (AFUNPTR) countInstrsAndSwitch,
                IARG_SPIN_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));*/
#if 0
        if (INS_HasFallThrough(tailIns) && BBL_InsHead(bbl) != tailIns) {
            pt.insertSwitchCall(tailIns, IPOINT_AFTER, (AFUNPTR) countInstrsAndSwitch,
                    IARG_SPIN_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }

        if (INS_IsBranchOrCall(tailIns) || INS_IsRet(tailIns)) {
            //pt.insertSwitchCall(tailIns, IPOINT_TAKEN_BRANCH, (AFUNPTR) countInstrsAndSwitch,
            //        IARG_SPIN_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }
#endif
    }
}

void nullCallback(spin::ThreadId tid) {
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) printf("Wrong args\n");
    spin::init(trace, threadStart, threadEnd, capture, uncapture);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}
