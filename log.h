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

#pragma once

template <typename ...Args>
void info(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    printf("[spin] %s\n", buf);
}

template <typename ...Args>
void panic(const char* fmt, Args... args) {
    char buf[1024];
    snprintf(buf, 1024, fmt, args...);
    fprintf(stderr, "[spin] Panic: %s\n", buf);
    fflush(stderr);
    exit(1);
}

