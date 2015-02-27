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
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <cstddef>

uint64_t baseiters;
volatile uint64_t x;

void* worker(void* arg) {
    uint64_t v = (uintptr_t)arg;
    printf("worker %ld\n", v);
    for (uint32_t i = 0; i < (v+1)*baseiters; i++) {
        __sync_fetch_and_add(&x, 1);
    }
    return nullptr;
}

int main(int argc, const char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <nthreads> <baseiters>\n", argv[0]);
    }
    uint32_t nthreads = atoi(argv[1]);
    baseiters = atoi(argv[2]);
    assert(nthreads > 0);
    printf("Running with %d threads, %ld base iters\n", nthreads, baseiters);
    
    pthread_t th[nthreads];
    for (uint32_t i = 1; i < nthreads; i++) {
        pthread_create(&th[i], nullptr, worker, (void*)(uintptr_t)i);
    }
    worker((void*)0);
    for (uint32_t i = 1; i < nthreads; i++) {
        pthread_join(th[i], nullptr);
    }
    printf("x: %ld\n", x);
    return 0;
}

