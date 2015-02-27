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

import os

# Get the mode flag from the command line
mode = ARGUMENTS.get('mode', 'opt')
allowedModes = ['debug', 'opt', 'release']
if mode not in allowedModes:
    print 'Error: invalid mode', mode, 'allowed:', allowedModes
    Exit(1)

env = Environment(ENV = os.environ)
env['CC'] = 'gcc-4.8'
env['CXX'] = 'g++-4.8'

env['CPPFLAGS'] = ['-std=c++11', '-Wall', '-Werror', '-Wno-unknown-pragmas',
    '-fomit-frame-pointer', '-fno-stack-protector', '-mavx']
env['CPPPATH'] = [os.path.abspath('include/')]

modeFlags = {
    'opt' : ['-O3','-gdwarf-3'],
    'release' : ['-O3', '-DNDEBUG', '-DNASSERT', '-gdwarf-3', '-march=native'],
    'debug' : ['-gdwarf-3'],
}
env.Append(CPPFLAGS = modeFlags[mode])

# Environment for library (paths assume Pin 2.14)
pinEnv = env.Clone()

pinEnv.Append(CPPFLAGS = ['-fPIC', '-MMD', '-DBIGARRAY_MULTIPLIER=1', '-DUSING_XED',
    '-DTARGET_IA32E', '-DHOST_IA32E', '-DTARGET_LINUX'])

PINPATH = os.environ['PIN_HOME'] if 'PIN_HOME' in os.environ \
          else os.environ['PINPATH']

pinEnv.Append(CPPPATH =
    [os.path.join(PINPATH, dir) for dir in (
    'extras/xed-intel64/include',
    'source/include',
    # [mcj] the following directory is only needed because pin doesn't use
    # relative paths correctly... weird
    'source/include/pin/gen',
    'extras/components/include')])

pinEnv.Append(LIBPATH = [os.path.join(PINPATH, dir) for dir in (
    'extras/xed-intel64/lib', 'intel64/lib', 'intel64/lib-ext')])

pinEnv.Append(LIBS = ['pin', 'xed', 'elf', 'dl', 'rt', 'pindwarf'])

pinverspath = os.path.join(PINPATH, 'source/include/pin/pintool.ver')
assert os.path.exists(pinverspath), pinverspath

pinEnv.Append(LINKFLAGS = ['-Wl,--hash-style=sysv',
    '-Wl,--version-script=' + pinverspath, '-Wl,-Bsymbolic', '-shared'])

(spinFast, spinSlow) = SConscript('lib/SConscript',
        variant_dir = os.path.join('build', mode, 'lib'),
        exports = {'env' : pinEnv},
        duplicate = 0)

# FIXME: Adding lib/ for mutex.h; tools should use a queue instead
pinEnv.Append(CPPPATH = [os.path.abspath("lib")])

fastEnv = pinEnv.Clone()
fastEnv['LIBS'] = [spinFast] + fastEnv['LIBS']
SConscript('tools/SConscript',
    variant_dir = os.path.join('build', mode, 'tools_fast'),
    exports = {'env' : fastEnv},
    duplicate = 0)

slowEnv = pinEnv.Clone()
slowEnv.Append(LIBS = [spinSlow], CPPFLAGS = '-DSPIN_SLOW')
SConscript('tools/SConscript',
    variant_dir = os.path.join('build', mode, 'tools_slow'),
    exports = {'env' : slowEnv},
    duplicate = 0)

testEnv = env.Clone()
testEnv.Append(LIBS = ['pthread'])
SConscript('tests/SConscript',
    variant_dir = os.path.join('build', mode, 'tests'),
    exports = {'env' : testEnv},
    duplicate = 0)
