# $lic$
# Copyright (C) 2015 by Massachusetts Institute of Technology
#
# This file is part of libspin.
#
# libspin is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, version 2.
#
# libspin is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

#######################################################################
# Assumes Pin v. 2.13 for the include, lib, and linker paths
#######################################################################
import os


env = Environment(ENV = os.environ)
env.Replace(CC = 'gcc-4.8')
env.Replace(CXX = 'g++-4.8 -O3')

localenv = env.Clone()

#pmp = localenv.SharedLibrary(
#    target='libpmp.so',
#    source="pmp.cpp")

localenv.Program(
    target='interleaver.so',
    source=["interleaver.cpp", "pmp.cpp"],)

localenv.Append(CPPFLAGS = ['-march=native', '-g', '-std=c++0x', '-Wall', '-Wno-unknown-pragmas',
    '-fomit-frame-pointer', '-fno-stack-protector', '-MMD', '-mavx',
    '-DBIGARRAY_MULTIPLIER=1', '-DUSING_XED', '-DTARGET_IA32E', '-DHOST_IA32E',
    '-fPIC', '-DTARGET_LINUX', '-DMT_SAFE_LOG'])

PINPATH = os.environ["PIN_HOME"] if "PIN_HOME" in os.environ \
          else os.environ["PINPATH"]

localenv.Append(CPPPATH =
    [os.path.join(PINPATH, dir) for dir in (
    'extras/xed-intel64/include',
    'source/include',
    # [mcj] the following directory is only needed because pin doesn't use
    # relative paths correctly... weird
    'source/include/pin/gen',
    'extras/components/include')])

localenv.Append(LIBPATH = [os.path.join(PINPATH, dir) for dir in (
    'extras/xed-intel64/lib', 'intel64/lib', 'intel64/lib-ext')])

# [mcj] copied from zsim SConstruct
# "Libdwarf is provided in static and shared variants, Ubuntu only provides
# static, and I don't want to add -R<pin path/intel64/lib-ext> because
# there are some other old libraries provided there (e.g. libelf) and I
# want to use the system libs as much as possible. So link directly to the
# static version of libdwarf."
localenv.Append(LIBS = ['pin', 'xed', 'elf', 'dl', 'rt',
    File(os.path.join(PINPATH, 'intel64/lib-ext/libpindwarf.a'))])

pinverspath = os.path.join(PINPATH, 'source/include/pin/pintool.ver')
assert os.path.exists(pinverspath), pinverspath

localenv.Append(LINKFLAGS = ['-Wl,--hash-style=sysv',
    '-Wl,--version-script=' + pinverspath, '-Wl,-Bsymbolic', '-shared'])


