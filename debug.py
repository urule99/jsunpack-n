#!/usr/bin/python
'''
    Jsunpackn - A generic JavaScript Unpacker Network Edition
    Copyright (C) 2010 Blake Hartstein
    http://jsunpack.jeek.org/

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
'''
from time import time

class DebugStats:
    '''Used to track performance statistics
    Within the application being debugged, you should not modify the members 
    directly. Instead, modify those elements by using the add* functions like 
    add_launch and add_detect

    Attributes:
    js_launches: One element for each times the SpiderMonkey js was called, could
                be either because there is a script error, also when evaluating 
                other versions of the environment.
    rule_detects: One element for each time running YARA detection.
    '''

    def __init__(self, name, tmpdir):
        self.name = name
        self.tmpdir = tmpdir
        self.js_launches = [] 
        self.rule_detects = []
        self.html_parsing = []
        self.total_js_launches = []
        self.total_rule_detects = []
        self.ignored_main = 0
        self.before_decode = None
        self.during_decode = None
        self.responsibility = None
        self.start = None

    def add_launch(self, script_filename):
        '''
        Adds a launch
        '''
        self.js_launches.append([{'filename':script_filename},
                                 self.end_timer()])
        self.total_js_launches.append([{'filename':script_filename},
                                     self.end_timer()])
        if self.end_timer() > 3:
            print 'add_launch %s/%s took %.02f ' % (self.name, script_filename,
                                                   self.end_timer())

    def add_detect(self, contents):
        '''
        Adds a detection
        '''
        self.rule_detects.append([{'len':len(contents)}, self.end_timer()])
        self.total_rule_detects.append([{'len':len(contents)},
                                        self.end_timer()])
        fout = open('%s/signature_%03d' % (self.tmpdir, self.end_timer()), 'wb')
        fout.write(contents)
        fout.close()

    def start_main(self):
        '''
        Start main
        '''
        self.before_decode = self.during_decode = time()
        self.responsibility = { 'init': 0, 'decoding':0, 'shellcode':0 }

    def record_main(self, record_type):
        '''
        Record main
        '''
        right_now = time()
        self.responsibility[record_type] = right_now - self.during_decode
        self.during_decode = right_now

    def finalize_main(self):
        '''
        Finalize main
        '''
        if time() - self.before_decode > 3:
            print ('main_decoder %s took %.02f seconds (ignored %d urls since '
                   'last print)' % (self.name[0:20],
                                    time() - self.before_decode,
                                    DebugStats.ignored_main))
            if (self.responsibility['init'] > 0.5 or 
                self.responsibility['shellcode'] > 1):
                print ('\t(%.02f init, %.02f decoding, %.02f sc)' 
                       % (self.responsibility['init'],
                          self.responsibility['decoding'],
                          self.responsibility['shellcode']))
            DebugStats.ignored_main = 0
        elif DebugStats.ignored_main >= 10:
            print ('main_decoder ignored %d urls since they are below threshold'
                   % (DebugStats.ignored_main))
            DebugStats.ignored_main = 0
        else:
            DebugStats.ignored_main += 1

    def add_timer(self):
        '''
        Add timer
        '''
        self.start = time()

    def end_timer(self):
        '''
        Get the time elapsed
        '''
        return (time() - self.start)

    def number_launches(self):
        '''
        Get the number of js lauches 
        '''
        return len(self.js_launches)

    def js_time(self):
        '''
        Js time
        '''
        secs = 0
        for js_lauches in self.js_launches:
            secs += js_lauches[1]
        return secs

    def detect_time(self):
        '''
        Detect times
        '''
        secs = 0
        for rule_detects in self.rule_detects:
            secs += rule_detects[1]
        return secs

    @staticmethod
    def number_total_launches():
        '''
        Get the number of how many times js has been Launched
        '''
        return len(DebugStats.total_js_launches)
        
    @staticmethod
    def total_js_time():
        '''
        Get the total runtime of all js lauches combined
        '''
        secs = 0
        for launches in DebugStats.total_js_launches:
            secs += launches[1]
        return secs

    @staticmethod
    def total_detect_time():
        '''
        Total detect time
        '''
        secs = 0
        for detects in DebugStats.total_rule_detects:
            secs += detects[1]
        return secs

    @staticmethod
    def reset_total_stats():
        '''
        Reset total stats
        '''
        DebugStats.total_js_launches = []
        DebugStats.total_rule_detects = []
