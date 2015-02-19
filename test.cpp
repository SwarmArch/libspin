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

#include <stdint.h>
#include <stdio.h>

__thread uint32_t y;

int main() {
    uint64_t x = 0;
    __asm__ __volatile__(
            "xchg %%rcx, %%rcx\n\t"\
            "addq $1, %0\n\t"\
            "xchg %%rdx, %%rdx"
            : "=r"(x) : "r"(x) : "rcx", "rdx");
    printf("x = %ld / %d\n", x, y);
    return 0;
}

