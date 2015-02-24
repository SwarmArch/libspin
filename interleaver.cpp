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
#include "pmp.h"

uint64_t syscallCount = 0;
uint64_t insCount = 0;
uint64_t loadCount = 0;
uint64_t threadStartCount = 0;
uint64_t threadEndCount = 0;

void fini(int tid, void* dummy) {
    fprintf(stderr, "Interleaver tool finished, stats:\n");
    fprintf(stderr, " instructions: %ld\n", insCount);
    fprintf(stderr, " loads: %ld\n", loadCount);
    fprintf(stderr, " threads: %ld starts, %ld ends\n", threadStartCount, threadEndCount);
    fprintf(stderr, " syscalls: %ld\n", syscallCount);
    fflush(stderr);
}

// Used to round-robin through threads
std::vector<uint32_t> threadVector;

// Forced-switch handling due to a syscall
uint32_t uncapture(pmp::ThreadContext* tc) {
/*    assert(!threadQueue.empty());  // pmp should not call this with a single thread
    uint32_t next = threadQueue.front();
    threadQueue.pop_front();
    return next;*/
    return -1; //FIXME
}

void capture(pmp::ThreadId tid) {
    //threadQueue.push_back(tid);
}

void threadStart(pmp::ThreadId tid) {
    threadVector.push_back(tid);
    threadStartCount++;
    printf("interleaver: threadStart\n");
}

void threadEnd(pmp::ThreadId tid) {
    threadEndCount++;
}


void countLoad() {
    loadCount++;
}

uint32_t countInstrsAndSwitch(const pmp::ThreadContext* tc, uint32_t instrs) {
    insCount += instrs;
    /*threadQueue.push_back(pmp::getThreadId(tc));
    uint32_t next = threadQueue.front();
    threadQueue.pop_front();*/
    uint32_t next = 0; //threadVector[rand() % threadVector.size()];
    //printf("switching to %d\n", next);
    return next;
}

void trace(TRACE trace, pmp::TraceInfo& pt) {
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
                    IARG_PMP_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }
#endif
        /*
        if (INS_IsBranchOrCall(tailIns) || INS_IsRet(tailIns)) {
            pt.insertSwitchCall(tailIns, IPOINT_TAKEN_BRANCH, (AFUNPTR) countInstrsAndSwitch,
                    IARG_PMP_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }

        pt.insertSwitchCall(tailIns, IPOINT_BEFORE, (AFUNPTR) countInstrsAndSwitch,
                IARG_PMP_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));*/
#if 0
        if (INS_HasFallThrough(tailIns) && BBL_InsHead(bbl) != tailIns) {
            pt.insertSwitchCall(tailIns, IPOINT_AFTER, (AFUNPTR) countInstrsAndSwitch,
                    IARG_PMP_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }

        if (INS_IsBranchOrCall(tailIns) || INS_IsRet(tailIns)) {
            //pt.insertSwitchCall(tailIns, IPOINT_TAKEN_BRANCH, (AFUNPTR) countInstrsAndSwitch,
            //        IARG_PMP_CONST_CONTEXT, IARG_UINT32, BBL_NumIns(bbl));
        }
#endif
    }
}

void nullCallback(pmp::ThreadId tid) {
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) printf("Wrong args\n");
    pmp::init(trace, threadStart, threadEnd, capture, uncapture);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}

