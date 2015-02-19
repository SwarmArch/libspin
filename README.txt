Pin Multiple personality library (libpmp) README
Author: Daniel Sanchez
Date: Jan 29 2015

Often, it is necessary to run a multithreaded application in Pin sequentially, intereleaving threads at fine granularity. For example, a single-threaded cycle-accurate simulator needs to switch threads every few instructions to simulate timing faithfully. PIN_SaveContext and ExecuteAt are too slow for this purpose, as they save and restore the huge thread context in full. They only support a few hundred thousand context-switches a second, limiting execution speed.

libpmp solves this problem, allowing about a billion context-switches per second at the expense of making code between context-switches somewhat slower. libpmp adds instrumentation to read and write registers from memory on each basic block or at a finer granularity (between every two posssible switch-points). By storing register in memory, a context-switch can be done through a simple jump. libpmp includes optimizations to reduce the overheads of register-memory transfers.

Main features:
- Can be used by your pintool without knowing the gory details
- Provides a simple interface to register perform context-switches
- Should work transparently to all applications, including handling of syscalls and exceptional conditions

Using libpmp:
1. Register switchpoints, i.e. points where context-switches can occur, at a trace granularity:
	pmp::registerSwitchpoints(Trace t, std::vector< std::tuple<instruction (int), ipoint (before/after)> >&);
2. Take switchpoints: In analysis calls that fall within a switchpoint, call:
	pmp::switch(tid); 
   The analysis function MUST return immediately after calling switch(). The switch will happen immediately after the return.
   If any analysis code (in this or another analysis function) runs between the call to switch() and the next switchpoint, behavior is UNDEFINED.

Compilation options:
   - slow just uses SaveContext and ExecuteAt.
   - checked uses partial saves and restores, and includes runtime checks to make sure you're not violating the API.
   - unchecked includes no such checks. Very fast, but if you break the contract it will fail in non-obvious ways.
