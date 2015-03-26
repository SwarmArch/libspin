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
#include <stdio.h>
#include <string.h>

int main() {
    const char* s = "Verify: OK\n";
    char buf[1024];

    strcpy(buf, "Verify: Incorrect REP STOSB\n");

    asm volatile("rep stosb" :: "c"(strlen(s)-1), "a"(42), "D"(buf) : "cc", "memory");

    puts(buf);

    memset(buf, 0, sizeof(buf));
    strcpy(buf, "REPNZ SCASB finds the first instance of a @ byte\n");
    int out = 1000;
    asm volatile("repnz scasb" : "=c"(out) : "c"(100), "a"('@'), "D"(buf) : "cc", "memory");
    int pos = 100 - out - 1;
    printf("%d %c\n", pos, buf[pos]);

    if (buf[pos] == '@') {
        puts(s);
    }

    return 0;
}





