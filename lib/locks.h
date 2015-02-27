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

#ifndef LOCKS_H_
#define LOCKS_H_

/* dsm: Futex lock from zsim, works inside Pin and across multiple processes */

#include <linux/futex.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>
#include <xmmintrin.h>

typedef volatile uint32_t lock_t;

static inline void futex_init(volatile uint32_t* lock) {
    *lock = 0;
    __sync_synchronize();
}

/* NOTE: The current implementation of this lock is quite unfair. Not that we care for its current use. */
static inline void futex_lock(volatile uint32_t* lock) {
    uint32_t c;
    do {
        for (int i = 0; i < 1000; i++) { //this should be tuned to balance syscall/context-switch and user-level spinning costs
            if (*lock == 0 && __sync_bool_compare_and_swap(lock, 0, 1)) {
                return;
            }
            _mm_pause();
        }

        //At this point, we will block
        c = __sync_lock_test_and_set(lock, 2); //this is not exactly T&S, but atomic exchange; see GCC docs
        if (c == 0) return;
        syscall(SYS_futex, lock, FUTEX_WAIT, 2, NULL, NULL, 0);
        c = __sync_lock_test_and_set(lock, 2); //atomic exchange
    } while (c != 0);
}

static inline void futex_lock_nospin(volatile uint32_t* lock) {
    uint32_t c;
    do {
        if (*lock == 0 && __sync_bool_compare_and_swap(lock, 0, 1)) {
            return;
        }

        //At this point, we will block
        c = __sync_lock_test_and_set(lock, 2); //this is not exactly T&S, but atomic exchange; see GCC docs
        if (c == 0) return;
        syscall(SYS_futex, lock, FUTEX_WAIT, 2, NULL, NULL, 0);
        c = __sync_lock_test_and_set(lock, 2); //atomic exchange
    } while (c != 0);
}

#define BILLION (1000000000L)
static inline bool futex_trylock_nospin_timeout(volatile uint32_t* lock, uint64_t timeoutNs) {
    if (*lock == 0 && __sync_bool_compare_and_swap(lock, 0, 1)) {
        return true;
    } else if (!timeoutNs) {
        return false;
    }

    //At this point, we will block
    uint32_t c = __sync_lock_test_and_set(lock, 2); //this is not exactly T&S, but atomic exchange; see GCC docs
    if (c == 0) return true;
    const struct timespec timeout = {(time_t) timeoutNs/BILLION, (time_t) timeoutNs % BILLION};
    syscall(SYS_futex, lock, FUTEX_WAIT, 2, &timeout, NULL, 0);
    c = __sync_lock_test_and_set(lock, 2); //atomic exchange
    if (c == 0) return true;
    return false;
}

static inline void futex_unlock(volatile uint32_t* lock) {
    if (__sync_fetch_and_add(lock, -1) != 1) {
        *lock = 0;
        /* This may result in additional wakeups, but avoids completely starving processes that are
         * sleeping on this. Still, if there is lots of contention in userland, this doesn't work
         * that well. But I don't care that much, as this only happens between phase locks.
         */
        syscall(SYS_futex, lock, FUTEX_WAKE, 1 /*wake next*/, NULL, NULL, 0);
    }
}

// Returns true if this futex has *detectable waiters*, i.e., waiters in the kernel
// There may still be waiters spinning, but if you (a) acquire the lock, and (b) want
// to see if someone is queued behind you, this will eventually return true
// No false positives (if true, for sure there's someone)
static inline bool futex_haswaiters(volatile uint32_t* lock) {
    return *lock == 2;
}

#endif  // LOCKS_H_
