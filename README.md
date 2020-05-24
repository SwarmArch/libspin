Sequential Pin library (libspin)
================================

Often, it is necessary to run a multithreaded application in Pin sequentially,
interleaving threads at fine granularity. For example, a single-threaded
cycle-accurate simulator needs to switch threads every few instructions to
simulate timing faithfully. ``PIN_SaveContext`` and ``PIN_ExecuteAt`` are too
slow for this purpose, as they save and restore the huge thread context in
full. They only support a few hundred thousand context-switches a second,
limiting execution speed.

libspin solves this problem, allowing about a billion context-switches per
second at the expense of making code between context-switches somewhat slower.
libspin adds instrumentation to read and write registers from memory on each
basic block or at a finer granularity (between every two possible
switch-points). By storing registers in memory, a context-switch can be done
through a simple jump. libspin includes optimizations to reduce the overheads
of register-memory transfers.

Main features:
- Can be used by your pintool without knowing the gory details
- Provides a simple interface to perform context-switches
- Should work transparently to all applications, including handling of syscalls
  and exceptional conditions
- Has a simple, slow implementation using SaveContext and ExecuteAt

Using libspin
-------------

Read the source of the simple, slow implementation, and the
examples/tests, to learn the interface. At a high level, libspin interposes on
all your analysis functions. Some of your analysis functions can be special
calls called switchcalls, which must return the next thread to switch to (or
the same thread if you do not wish to switch). Switchcalls are always run
before normal analysis functions.

libspin was developed as an internal component of the Swarm architecture
simulator, so if you are building your own simulator, we recommend checking the
Swarm simulator source for usage examples.

Copyright & License
-------------------

Copyright (C) 2015-2020 by Massachusetts Institute of Technology

libspin is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, version 2.

Additionally, if you use this software in your research, we request that you
reference the Swarm paper ("A Scalable Architecture for Ordered Parallelism",
Jeffrey et al., MICRO-48, 2015) as the source of libspin in any publications
that use this software, and that you send us a citation of your work.

