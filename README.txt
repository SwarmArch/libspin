Sequential Pin library (libspin) README
Author: Daniel Sanchez
Date: Feb 2015

Often, it is necessary to run a multithreaded application in Pin sequentially,
interleaving threads at fine granularity. For example, a single-threaded
cycle-accurate simulator needs to switch threads every few instructions to
simulate timing faithfully. PIN_SaveContext and ExecuteAt are too slow for this
purpose, as they save and restore the huge thread context in full. They only
support a few hundred thousand context-switches a second, limiting execution
speed.

libspin solves this problem, allowing about a billion context-switches per
second at the expense of making code between context-switches somewhat slower.
libspin adds instrumentation to read and write registers from memory on each
basic block or at a finer granularity (between every two posssible
switch-points). By storing registers in memory, a context-switch can be done
through a simple jump. libspin includes optimizations to reduce the overheads
of register-memory transfers.

Main features:
- Can be used by your pintool without knowing the gory details
- Provides a simple interface to perform context-switches
- Should work transparently to all applications, including handling of syscalls
  and exceptional conditions
- Has a simple, slow implementation using SaveContext and ExecuteAt

Using libspin: Read the source of the simple, slow implementation, and the
examples/tests, to learn the interface. At a high level, libspin interposes on
all your analysis functions. Some of your analysis functions can be speciall
calls called switchcalls, which must return the next thread to switch to (or
the same thread if you do not wish to switch). Switchcalls are always run
before normal analysis functions.

