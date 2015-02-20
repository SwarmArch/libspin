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
    printf("Interleaver tool finished, stats:\n");
    printf(" instructions: %ld\n", insCount);
    printf(" loads: %ld\n", loadCount);
    printf(" threads: %ld starts, %ld ends\n", threadStartCount, threadEndCount);
    printf(" syscalls: %ld\n", syscallCount);
}

// Used to round-robin through threads
std::deque<uint32_t> threadQueue;

// Forced-switch handling due to a syscall
uint32_t syscallSwitch(pmp::ThreadContext* tc) {
    assert(!threadQueue.empty());  // pmp should not call this with a single thread
    uint32_t next = threadQueue.front();
    threadQueue.pop_front();
    return next;
}

void countLoad() {
    loadCount++;
}

uint32_t countInstrsAndSwitch(const pmp::ThreadContext* tc, uint32_t instrs) {
    insCount += instrs;
    threadQueue.push_back(pmp::getThreadId(tc));
    uint32_t next = threadQueue.front();
    threadQueue.pop_front();
    return next;
}

void threadStart(pmp::ThreadId tid) {
    threadQueue.push_back(tid);
    threadStartCount++;
}

void threadEnd(pmp::ThreadId tid) {
    threadEndCount++;
}

void trace(TRACE trace, pmp::TraceInfo& pt) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryRead(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
            if (INS_HasMemoryRead2(ins)) pt.insertCall(ins, IPOINT_BEFORE, (AFUNPTR) countLoad);
        }

        INS tailIns = BBL_InsTail(bbl);
        if (INS_HasFallThrough(tailIns)) {
            pt.insertSwitchCall(tailIns, IPOINT_AFTER, (AFUNPTR) countInstrsAndSwitch,
                    IARG_PMP_CONST_CONTEXT, BBL_NumIns(bbl));
        }
        if (INS_IsBranchOrCall(tailIns) || INS_IsRet(tailIns)) {
            pt.insertSwitchCall(tailIns, IPOINT_TAKEN_BRANCH, (AFUNPTR) countInstrsAndSwitch,
                    IARG_PMP_CONST_CONTEXT, BBL_NumIns(bbl));
        }
    }
}

void nullCallback(pmp::ThreadId tid) {
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) printf("Wrong args\n");
    pmp::init(trace, threadStart, threadEnd, nullCallback, nullCallback);
    PIN_AddFiniFunction(fini, 0);
    PIN_StartProgram();
    return 0;
}

