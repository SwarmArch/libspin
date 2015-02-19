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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <cstddef>

volatile int x;

void* worker(void* arg) {
    uint64_t v = (uintptr_t)arg;
    printf("%ld\n", v);
    for (uint32_t i = 0; i < (v+1)*100000; i++) {
        __sync_fetch_and_add(&x, 1);
    }
}

int main() {
    pthread_t th;
    pthread_create(&th, nullptr, worker, (void*)1);
    worker((void*)2);
    pthread_join(th, nullptr);
    printf("x: %ld\n", x);
    return 0;
}

