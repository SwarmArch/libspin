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

env['CPPFLAGS'] = ['-std=c++11', '-Wall', '-Werror', '-Wno-unknown-pragmas',
    '-fomit-frame-pointer', '-fno-stack-protector']
env['CPPPATH'] = [os.path.abspath('include/')]

modeFlags = {
    'opt' : ['-O3','-gdwarf-3'],
    'release' : ['-O3', '-DNDEBUG', '-DNASSERT', '-gdwarf-3', '-Wno-unused-variable'],
    'debug' : ['-O0', '-gdwarf-3'],
}
env.Append(CPPFLAGS = modeFlags[mode])

# AVX is required by spin-fast; this compiles SNB(mad/draco)-compatible code from anywhere
# If you want to run on an architecture without AVX, make it a scons option,
# don't make the flags depend on the compiling machine.
archFlags = ['-march=corei7-avx', '-mavx', '-msse4.1', '-msse4.2']
env.Append(CPPFLAGS = archFlags)

# Environment for library (paths assume Pin 2.14)
pinEnv = env.Clone()

pinEnv.Append(CPPFLAGS = ['-fPIC', '-MMD'])
pinEnv.Append(CPPDEFINES = [('BIGARRAY_MULTIPLIER',1), 'USING_XED',
    'TARGET_IA32E', 'HOST_IA32E', 'TARGET_LINUX'])

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

pinEnv.Append(LIBS = ['pin', 'xed', 'dl', 'rt', 'pindwarf'])

pinverspath = os.path.join(PINPATH, 'source/include/pin/pintool.ver')
assert os.path.exists(pinverspath), pinverspath

pinEnv.Append(LINKFLAGS = ['-Wl,--hash-style=sysv',
    '-Wl,--version-script=' + pinverspath, '-Wl,-Bsymbolic', '-shared'])

genericToolEnv = pinEnv.Clone()

for speed in ['slow', 'fast']:
    spinLib = SConscript('lib/SConscript',
        variant_dir = os.path.join('build', mode, 'lib'),
        exports = {'env' : pinEnv, 'speed' : speed},
        duplicate = 0)

    toolEnv = genericToolEnv.Clone()
    toolEnv.Prepend(LIBS = [spinLib])
    if speed == 'slow':
        toolEnv.Append(CPPDEFINES = 'SPIN_SLOW')

    SConscript('tools/SConscript',
        variant_dir = os.path.join('build', mode, 'tools_{}'.format(speed)),
        exports = {'env' : toolEnv},
        duplicate = 0)

testEnv = env.Clone()
testEnv.Append(LIBS = ['pthread'])
SConscript('tests/SConscript',
    variant_dir = os.path.join('build', mode, 'tests'),
    exports = {'env' : testEnv},
    duplicate = 0)
