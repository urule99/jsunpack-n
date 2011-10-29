#!/usr/bin/python
'''
Debug class - This is used by the Jsunpackn project to track performance 
statistics

Within the application being debugged, you should not modify the members 
directly. Instead, modify those elements by using the add* functions like 
addLaunch and addDetect
'''
import time

class DebugStats:
    totalJsLaunches = []
    totalRuleDetects = []
    ignored_main = 0

    def __init__(self, name, tmpdir):
        self.name = name
        self.tmpdir = tmpdir
        self.jsLaunches = []    # element for each times the SpiderMonkey js was called
                                # could be either because there is a script error 
                                # also when evaluating other versions of the environment

        self.ruleDetects = []   # element for each time running YARA detection
        self.htmlParsing = []



    def addLaunch(self, scriptFilename):
        self.jsLaunches.append([{'filename':scriptFilename}, self.endTimer()])
        self.totalJsLaunches.append([{'filename':scriptFilename}, self.endTimer()])
        if self.endTimer() > 3:
            print 'addLaunch %s/%s took %.02f ' % (self.name, scriptFilename, self.endTimer())

    def addDetect(self, contents):
        self.ruleDetects.append([{'len':len(contents)}, self.endTimer()])
        self.totalRuleDetects.append([{'len':len(contents)}, self.endTimer()])        
        fout = open('%s/signature_%03d' % (self.tmpdir, self.endTimer()), 'wb')
        fout.write(contents)
        fout.close()

    def start_main(self):
        self.before_decode = self.during_decode = time.time()
        self.responsibility = { 'init': 0, 'decoding':0, 'shellcode':0 }

    def record_main(self, type):
        right_now = time.time()
        self.responsibility[type] = right_now - self.during_decode
        self.during_decode = right_now

    def finalize_main(self):
        if time.time() - self.before_decode > 3:
            print 'main_decoder %s took %.02f seconds (ignored %d urls since last print)' % (self.name[0:20], time.time() - self.before_decode, DebugStats.ignored_main)
            if self.responsibility['init'] > 0.5 or self.responsibility['shellcode'] > 1:
                print '\t(%.02f init, %.02f decoding, %.02f sc)' % (self.responsibility['init'], self.responsibility['decoding'], self.responsibility['shellcode'])
            DebugStats.ignored_main = 0
        elif DebugStats.ignored_main >= 10:
            print 'main_decoder ignored %d urls since they are below threshold' % (DebugStats.ignored_main)
            DebugStats.ignored_main = 0
        else:
            DebugStats.ignored_main += 1

    def addTimer(self):
        self.start = time.time()

    def endTimer(self):
        return (time.time() - self.start)

    def numberLaunches(self):
        return len(self.jsLaunches)

    def jsTime(self):
        secs = 0
        for name, elapsed in self.jsLaunches:
            secs += elapsed
        return secs

    def detectTime(self):
        secs = 0
        for datalen, elapsed in self.ruleDetects:
            secs += elapsed
        return secs

    @staticmethod
    def numberTotalLaunches():
        return len(DebugStats.totalJsLaunches)
        
    @staticmethod
    def totalJsTime():
        secs = 0
        for name, elapsed in DebugStats.totalJsLaunches:
            secs += elapsed
        return secs

    @staticmethod
    def totalDetectTime():
        secs = 0
        for datalen, elapsed in DebugStats.totalRuleDetects:
            secs += elapsed
        return secs

    @staticmethod
    def resetTotalStats():
        DebugStats.totalJsLaunches = []
        DebugStats.totalRuleDetects = []

