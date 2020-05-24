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

#ifndef PAD_H_
#define PAD_H_

/* Padding macros to remove false sharing */

/* _Host_ line size in bytes. */
#define CACHE_LINE_BYTES (64)

#define _PAD_CONCAT(x, y) x ## y
#define PAD_CONCAT(x, y) _PAD_CONCAT(x, y)

#define PAD() unsigned char PAD_CONCAT(pad_line, __LINE__)[CACHE_LINE_BYTES] //assuming classes are defined over one file, this should generate unique names

//Pad remainder to line size, use as e.g. PAD(sizeof(uint32)) will produce 60B of padding
#define PAD_SZ(sz) unsigned char PAD_CONCAT(pad_sz_line, __LINE__)[CACHE_LINE_BYTES - ((sz) % CACHE_LINE_BYTES)]

#define ATTR_LINE_ALIGNED __attribute__((aligned(CACHE_LINE_BYTES)))

#endif  // PAD_H_
