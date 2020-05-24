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

#ifndef ASSERT_H_
#define ASSERT_H_

#include "log.h"
#include <sstream>

// assertions are often frequently executed but never taken. Might as well tell the compiler about it
#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

/* Helper class to print expression with values
 * Inpired by Phil Nash's CATCH, https://github.com/philsquared/Catch
 * const enough that asserts that use this are still optimized through
 * loop-invariant code motion
 */
class PrintExpr {
    private:
        std::stringstream& ss;

    public:
        PrintExpr(std::stringstream& _ss) : ss(_ss) {}

        // Start capturing values
        template<typename T> const PrintExpr operator->* (T t) const { ss << t; return *this; }

        // Overloads for all lower-precedence operators
        template<typename T> const PrintExpr operator == (T t) const { ss << " == " << t; return *this; }
        template<typename T> const PrintExpr operator != (T t) const { ss << " != " << t; return *this; }
        template<typename T> const PrintExpr operator <= (T t) const { ss << " <= " << t; return *this; }
        template<typename T> const PrintExpr operator >= (T t) const { ss << " >= " << t; return *this; }
        template<typename T> const PrintExpr operator <  (T t) const { ss << " < "  << t; return *this; }
        template<typename T> const PrintExpr operator >  (T t) const { ss << " > "  << t; return *this; }
        template<typename T> const PrintExpr operator &  (T t) const { ss << " & "  << t; return *this; }
        template<typename T> const PrintExpr operator |  (T t) const { ss << " | "  << t; return *this; }
        template<typename T> const PrintExpr operator ^  (T t) const { ss << " ^ "  << t; return *this; }
        template<typename T> const PrintExpr operator && (T t) const { ss << " && " << t; return *this; }
        template<typename T> const PrintExpr operator || (T t) const { ss << " || " << t; return *this; }
        template<typename T> const PrintExpr operator +  (T t) const { ss << " + "  << t; return *this; }
        template<typename T> const PrintExpr operator -  (T t) const { ss << " - "  << t; return *this; }
        template<typename T> const PrintExpr operator *  (T t) const { ss << " * "  << t; return *this; }
        template<typename T> const PrintExpr operator /  (T t) const { ss << " / "  << t; return *this; }
        template<typename T> const PrintExpr operator %  (T t) const { ss << " % "  << t; return *this; }
        template<typename T> const PrintExpr operator << (T t) const { ss << " << " << t; return *this; }
        template<typename T> const PrintExpr operator >> (T t) const { ss << " >> " << t; return *this; }

        // std::nullptr_t overloads (for nullptr's in assertions)
        // Only a few are needed, since most ops w/ nullptr are invalid
        const PrintExpr operator->* (std::nullptr_t t) const { ss << "nullptr"; return *this; }
        const PrintExpr operator == (std::nullptr_t t) const { ss << " == nullptr"; return *this; }
        const PrintExpr operator != (std::nullptr_t t) const { ss << " != nullptr"; return *this; }

    private:
        template<typename T> const PrintExpr operator =  (T t) const;  // will fail, can't assign in assertion
};

#ifndef NASSERT
#define assert(expr) \
if (unlikely(!(expr))) { \
    std::stringstream __assert_ss__LINE__; (PrintExpr(__assert_ss__LINE__)->*expr); \
    panic("Failed assertion on %s:%d '%s' (with '%s')\n", __FILE__, __LINE__, #expr, __assert_ss__LINE__.str().c_str()); \
};
#else
// Avoid unused warnings, never emit any code
// see http://cnicholson.net/2009/02/stupid-c-tricks-adventures-in-assert/
#define assert(cond) do { (void)sizeof(cond); } while (0);
#endif

#endif  // ASSERT_H_
