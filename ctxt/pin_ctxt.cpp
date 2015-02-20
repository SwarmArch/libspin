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

//#define info(args...)
#define info(args...) {printf(args); printf("\n"); }

CONTEXT sCtxt;

uint64_t left = 1000000;

void Point1(const CONTEXT* ctxt) {
    //info("point1");
    PIN_SaveContext(ctxt, &sCtxt);
}

void Point2(const CONTEXT* ctxt) {
    //info("point2");
    ADDRINT x = PIN_GetContextReg(ctxt, REG_RAX);
    PIN_SetContextReg(&sCtxt, REG_RAX, x);
    if (--left) PIN_ExecuteAt(&sCtxt);
}

void Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RCX && INS_OperandReg(ins, 1) == REG_RCX) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) Point1, IARG_CONST_CONTEXT, IARG_END);
            }
            if (INS_IsXchg(ins) && INS_OperandReg(ins, 0) == REG_RDX && INS_OperandReg(ins, 1) == REG_RDX) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) Point2, IARG_CONST_CONTEXT, IARG_END);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) info("Wrong args");

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_StartProgram();
    return 0;
}
