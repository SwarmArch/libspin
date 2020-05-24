/** $lic$
 * Copyright (C) 2015-2020 by Massachusetts Institute of Technology
 *
 * This file is part of libspin.
 *
 * libspin is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 2.
 *
 * libspin was developed as part of the Swarm architecture simulator. If you
 * use this software in your research, we request that you reference the Swarm
 * paper ("A Scalable Architecture for Ordered Parallelism", Jeffrey et al.,
 * MICRO-48, 2015) as the source of libspin in any publications that use this
 * software, and that you send us a citation of your work.
 *
 * libspin is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_H_
#define LOG_H_

#include <stdio.h>
#include <stdlib.h>
#include "mutex.h"

extern mutex logMutex;

static inline void info(const char* str) {
    scoped_mutex sm(logMutex);
    fprintf(stdout, "[spin] %s\n", str);
    fflush(stdout);
}

template <typename ...Args>
static void info(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    info(buf);
}

static inline void panic(const char* str) {
    logMutex.lock();
    fprintf(stderr, "[spin] Panic: %s\n", str);
    fflush(stderr);
    logMutex.unlock();
    exit(1);
}

template <typename ...Args>
static void panic(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    panic(buf);
}

#endif  // LOG_H_
