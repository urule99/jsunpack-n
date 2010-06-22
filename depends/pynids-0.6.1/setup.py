#! /usr/bin/env python

# setup.py - Distutils instructions for the pynids package

# This file is part of the pynids package, a python interface to libnids.
# See the file COPYING for license information.

from distutils.core import setup, Extension
from distutils.command.build import build    # nidsMaker
from distutils.spawn import spawn            # nidsMaker.run()
import os, os.path

pathjoin = os.path.join

PKGNAME  = 'libnids-1.24'
PKGTAR   = PKGNAME + '.tar.gz'
BUILDDIR = PKGNAME

INCLUDE_DIRS  = ['/usr/local/include', '/opt/local/include']
LIBRARY_DIRS  = ['/usr/local/lib', '/opt/local/lib']
EXTRA_OBJECTS = []

class nidsMaker(build):
    NIDSTAR = PKGTAR
    NIDSDIR = BUILDDIR
    include_dirs = [ pathjoin(NIDSDIR, 'src') ]
    library_dirs = []
    extra_objects  = [ pathjoin(NIDSDIR, 'src', 'libnids.a') ]

    def buildNids(self):
        # extremely crude package builder
        try:
            os.stat(self.NIDSDIR)
            return None           # assume already built
        except OSError:
            pass

        spawn(['tar', '-zxf', self.NIDSTAR], search_path = 1)
        os.chdir(self.NIDSDIR)
        spawn([pathjoin('.','configure'), 'CFLAGS=-fPIC'])
        spawn(['make'], search_path = 1)
        os.chdir('..')

    def run(self):
        self.buildNids()
        build.run(self)

INCLUDE_DIRS = nidsMaker.include_dirs + INCLUDE_DIRS
EXTRA_OBJECTS = nidsMaker.extra_objects + EXTRA_OBJECTS

setup (# Distribution meta-data
        name = "pynids",
        version = "0.6.1",
        description = "libnids wrapper",
        author = "Jon Oberheide",
        author_email = "jon@oberheide.org",
        license = "GPL",
        long_description = \
'''pynids is a python wrapper for libnids, a Network Intrusion Detection System
library offering sniffing, IP defragmentation, TCP stream reassembly and TCP
port scan detection.
-------
''',
        cmdclass = {'build': nidsMaker},
        ext_modules = [ Extension(
                            "nidsmodule",
                            #define_macros = [ ("DEBUG", None), ],
                            sources=["nidsmodule.c"],
                            include_dirs = INCLUDE_DIRS,
                            libraries = ["pcap", "net", "glib-2.0", "gthread-2.0"],
                            library_dirs = LIBRARY_DIRS,
                            extra_objects = EXTRA_OBJECTS
                        ) 
                      ],
        url = "http://jon.oberheide.org/pynids/",
      )
