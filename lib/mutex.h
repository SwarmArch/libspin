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

#ifndef __MUTEX_H__
#define __MUTEX_H__

#include "locks.h"
#include "pad.h"

class mutex {
    private:
        volatile uint32_t futex;
    public:
        mutex() { futex_init(&futex); }
        void lock() { futex_lock(&futex); }
        void unlock() { futex_unlock(&futex); }
        bool haswaiters() { return futex_haswaiters(&futex); }
};

class aligned_mutex : public mutex {} ATTR_LINE_ALIGNED;

class scoped_mutex {
    private:
        mutex* mut;
    public:
        scoped_mutex(mutex& _mut) : mut(&_mut) { mut->lock(); }
        scoped_mutex() : mut(0) {}
        ~scoped_mutex() { if (mut) mut->unlock(); }
};

#endif /*__MUTEX_H__*/
