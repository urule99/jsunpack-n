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
#See included INSTALL file for installation instructions
#See included CHANGELOG file for features

from hashlib import sha1
from optparse import OptionParser
from os import makedirs
from os.path import isdir, abspath, dirname
from urlattr import *
import ConfigParser
import StringIO
import detection
import gzip
import html
import pdf
import random
import signal
import socket
import struct
import subprocess
import swf
import sys
import time
import urllib2

try:
    import magic #optional
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    ENABLE_MAGIC = True
except:
    ENABLE_MAGIC = False

try:
    import nids #optional
    end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
    ENABLE_NIDS = True
except ImportError:
    ENABLE_NIDS = False

class jsunpack:
    version = "0.3.2c (beta)"
    defaultReferer = 'www.google.com/trends/hottrends' #used by active fetching only
    ips = []

    def __init__(self, _start, todecode, options, prevRooturl={}) :
        '''
        INPUT: These are the main input modes:
            1) options.urlfetch: URL to fetch and decode (if options.active, then follow up)
                OR
            2) todecode: local contents or static string as:
                todecode[0]=url_or_name(optional)
                todecode[1]=data(mandatory)
                todecode[2]=filename

        OUTPUT: check the <jsunpack Object>.rooturl structure. To decode multiple files and not create separate trees,
            passing rooturl between different decodings is necessary (as prevRooturl).

        parameters:
            @_start = url of root node
            @options = configuration and user settings; includes rules as strings (not filenames)
            @prevRooturl = continuity of tree between decodings, after decoding pass in <jsunpack Object>.rooturl
        '''
        global ENABLE_NIDS
        self.start = canonicalize(_start) #start is the root node in the tree, do not destroy it
        self.rooturl = prevRooturl #this dict contains all information about decodings, continuity between decodings

        [myurl, mydata, myfile] = todecode
        self.url = myurl

        self.forceStreams = False #keep data in streams{} in case we don't end in one of the end_states
        self.streams = {}
        self.seen = {} #dictionary to avoid repeating information (addressed by unique url)

        #detection:
        #self.exploits = [] #legacy
        self.SIGS = detection.rules(options.rules)
        self.SIGSalt = detection.rules(options.rulesAscii)

        #options and attributes:
        self.OPTIONS = options #configuration and user options
        self.lastModified = '' #http_header lastModified
        self.binExists = False
        if self.OPTIONS.veryverbose:
            self.OPTIONS.verbose = True
        if self.OPTIONS.verbose:
            urlattr.verbose = True

        self.OPTIONS.outdir = self.replaceCurrentDate(self.OPTIONS.outdir)
        self.OPTIONS.tmpdir = self.replaceCurrentDate(self.OPTIONS.tmpdir)
        if not hasattr(self.OPTIONS, 'log_ips'):
            self.OPTIONS.log_ips = ''
        self.OPTIONS.log_ips = self.replaceCurrentDate(self.OPTIONS.log_ips)
        if not hasattr(self.OPTIONS, 'decoded'):
            self.OPTIONS.decoded = ''
        self.OPTIONS.decoded = self.replaceCurrentDate(self.OPTIONS.decoded)

        self.hparser = html.Parser(self.OPTIONS.htmlparseconfig)
        if not isdir(abspath(self.OPTIONS.tmpdir)):
            try:
                makedirs(abspath(self.OPTIONS.tmpdir))
            except Exception, e:
                print(e)
                exit(1)
        if not isdir(abspath(self.OPTIONS.outdir)):
            try:
                makedirs(abspath(self.OPTIONS.outdir))
            except Exception, e:
                print(e)
                exit(1)
        if not isdir(abspath(dirname(self.OPTIONS.log_ips))):
            try:
                makedirs(abspath(dirname(self.OPTIONS.log_ips)))
            except Exception, e:
                print(e)
                exit(1)
        if not isdir(abspath(dirname(self.OPTIONS.decoded))):
            try:
                makedirs(abspath(dirname(self.OPTIONS.decoded)))
            except Exception, e:
                print(e)
                exit(1)


        #done setup, now initialize the decoding
        self.startTime = time.time()
        self.NIDS_INIALIZED = False #don't initialize nids twice!

        if self.OPTIONS.interface:
            nids.param('device', self.OPTIONS.interface)
            self.run_nids()

        elif self.OPTIONS.urlfetch:
            if not self.OPTIONS.quiet:
                print 'URL fetch %s' % (self.OPTIONS.urlfetch)
            status, fname = self.fetch(options.urlfetch)
            if not self.OPTIONS.quiet:
                print status

        else: #local file decode
            if not self.url:
                if myfile:
                    self.url = myfile #use filename as the root
            if self.url and (not self.url in self.rooturl):
                self.rooturl[self.url] = urlattr(self.rooturl, self.start)

            if mydata:
                self.rooturl[self.url].setMalicious(urlattr.ANALYZED)
                if mydata.startswith('\xD4\xC3\xB2\xA1'): #pcap
                    if ENABLE_NIDS:
                        self.run_nids(myfile)
                    else:
                        print '[warning] %s not scanned because pynids ("import nids") failed' % (file)
                else:
                    self.main_decoder(mydata, myfile)

        if self.OPTIONS.active:
            todo = []
            firstTime = True

            while todo or firstTime:
                firstTime = False
                if (not self.OPTIONS.quiet) and len(todo) > 0:
                    print 'Active Mode, fetching %d new URLs' % (len(todo))
                while todo:
                    url = todo.pop()
                    status, fname = self.fetch(url)
                    self.rooturl[url].setMalicious(urlattr.ANALYZED)

                    if not self.OPTIONS.quiet:
                        type = ''
                        if self.rooturl[url].type:
                            type = '(%s) ' % (self.rooturl[url].type)
                        if not self.OPTIONS.quiet:
                            print '\tfetching URL %s%s' % (type, url) + status

                for url in self.rooturl:
                    if self.rooturl[url].malicious == urlattr.NOT_ANALYZED:
                        if not (self.rooturl[url].type == 'img' or self.rooturl[url].type == 'input' or self.rooturl[url].type == 'link'):
                            todo.append(url)

    def replaceCurrentDate(self, variable):
        curdate = variable.find('$CURDATE')
        if curdate > -1:
            yr, mo, day = time.gmtime()[0:3]
            before = ''
            if curdate > 0:
                before = variable[0:curdate]
            after = variable[curdate + len('$CURDATE'):]

            variable = '%s%04d%02d%02d%s' % (before, yr, mo, day, after)
        return variable


    def decodeVersions(self, to_write, isPDF):
        decodings = [] #there may be multiple decodings if we get different results for version strings
        duration = 0 #total elapsed time
        runningTime = 0 #previous evaluation time

        if isPDF:
            pdfversions = ['', '9.1']
            if not self.OPTIONS.fasteval:
                pdfversions.append('8.0')
                pdfversions.append('7.0')

            for pdfversion in pdfversions: #if the runningTime is short, try these alternative versions
                if duration < self.OPTIONS.timeout and runningTime <= self.OPTIONS.redoevaltime:
                    env_vars = 'app.viewerVersion = Number(%s);\n' % (pdfversion)

                    decoded, currentRunningTime = self.decodeJShelper('%s%s' % (env_vars, to_write))
                    runningTime = currentRunningTime
                    duration += currentRunningTime
                    decodings.append(['app.viewerVersion=' + pdfversion, decoded])

        else:
            need_to_write = 'var location = new my_location("%s","%s"); \n%s\n' % (self.url, self.url, to_write)
            if not self.OPTIONS.fasteval: #don't evaluate HTML en/zh-cn in favor of performance
                for lang in ['en', 'zh-cn']:
                    if duration < self.OPTIONS.timeout and runningTime <= self.OPTIONS.redoevaltime:
                        env_vars = 'navigator.systemLanguage=String("%s"); ' % lang
                        env_vars += 'navigator.browserLanguage=String("%s"); ' % lang
                        env_vars += 'document.lastModified=String("%s");\n' % re.sub('"', '', self.lastModified)
                        decoded, currentRunningTime = self.decodeJShelper('%s%s' % (env_vars, need_to_write))
                        runningTime = currentRunningTime
                        duration += currentRunningTime
                        decodings.append(['navigator.systemLanguage=' + lang, decoded])

            browsers = [    ['IE7/XP', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'] ]

            if not self.OPTIONS.fasteval:
                browsers.append(['IE8/Vista', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'])
                browsers.append(['Opera', 'Opera/9.64 (Windows NT 6.1; U; de) Presto/2.1.1'])
                browsers.append(['Firefox', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)'])
            for name, browser in browsers:
                if duration < self.OPTIONS.timeout and runningTime <= self.OPTIONS.redoevaltime:
                    midpoint = browser.find('/')
                    appCodeName = browser[:midpoint]
                    appVersion = browser[midpoint + 1:]
                    decoded, currentRunningTime = self.decodeJShelper('navigator.appCodeName = String("%s"); navigator.appVersion = String("%s"); navigator.userAgent = String("%s"); document.lastModified = String("%s");\n%s' % (appCodeName, appVersion, browser, self.lastModified, need_to_write))
                    runningTime = currentRunningTime
                    duration += currentRunningTime
                    decodings.append(['browser=' + name, decoded])

        return decodings

    def decodeJS(self, content, isPDF):
        #return values are:
        #(decoded scripts)
        try:
            to_write_headers, to_write = self.hparser.htmlparse(content)
        except Exception, e:
            to_write_headers, to_write = '', '' #print 'Error in htmlparsing', str(e)

        if len(to_write) > 0: #html parse succeeded
            to_write = to_write_headers + to_write
            decodings = self.decodeVersions(to_write, isPDF)

            #redo decoding if we didn't decode anything
            if not self.OPTIONS.fasteval: #in performance optimized version, we should not evaluate this option
                redo = 1
                for version, decoding in decodings:
                    if len(decoding) > 0:
                        redo = 0
                if redo:
                    #its possible that HTML parsing failed, then we should process the original content
                    more_decode = self.decodeVersions(content, isPDF)
                    for decode in more_decode:
                        decodings.append(decode)

        else: #html parse failed (or was empty), treat original 'content' as JavaScript
            decodings = self.decodeVersions(content, isPDF)

        winner = ''
        lengths = {}
        for version, decoding in decodings:
            thislen = len(decoding)
            if len(decodings) > 1:
                key = '%d' % (thislen)
                if key in lengths:
                    lengths[key].append(version)
                else:
                    lengths[key] = [version]

            if thislen > len(winner):
                winner = decoding

        if len(lengths) > 1:
            for a in lengths:
                self.rooturl[self.url].log(self.OPTIONS.veryverbose, 0, 'Decoding option %s, \t%s bytes' % (' and '.join(lengths[a]), a))

        return winner

    def decodeJShelper(self, to_write, fixErrors=3):
        if fixErrors > 1 and self.OPTIONS.fasteval:
            fixErrors = 1

        current_filename = '%s/tmpsha1_%s' % (self.OPTIONS.tmpdir, sha1(to_write).hexdigest())
        fout = open(current_filename + '.js', 'wb')
        if fout:
            to_write = re.sub('\0', '', to_write)
            fout.write(to_write)
            fout.close()
        else:
            print 'Error: writing to tmpfile %s' % current_filename
            return '', 0

        decoded = errors = ''
        begin = time.time()
        try:
            js_stdout = open(current_filename + '.stdout', 'wb')
            js_stderr = open(current_filename + '.stderr', 'wb')

            if self.OPTIONS.debug:
                self.rooturl[self.url].dbgobj.add_timer()

            if not (os.path.exists(self.OPTIONS.pre) and os.path.exists(self.OPTIONS.post)):
                exit("Fatal: Failed to find pre.js and post.js")

            po = subprocess.Popen(['js', '-f', self.OPTIONS.pre, '-f', current_filename + '.js', '-f', self.OPTIONS.post], shell=False, stdout=js_stdout, stderr=js_stderr)

            timeLimitExceededReason = ''
            while not timeLimitExceededReason and po.poll() == None:
                curTime = time.time()

# Checking various timeouts -- if a timeout is hit, we'll break out of this while loop of polling doom.
                if self.OPTIONS.timeout > 0 and (curTime - begin) >= self.OPTIONS.timeout:
                    timeLimitExceededReason = 'script analysis exceeded %d seconds (incomplete)' % (self.OPTIONS.timeout)
                    fixErrors = 0 #don't recurse into this function

                elif self.OPTIONS.maxruntime > 0 and (curTime - self.startTime) >= self.OPTIONS.maxruntime:
                    timeLimitExceededReason = 'maxruntime exceeded %d seconds (incomplete)' % self.OPTIONS.maxruntime
                    self.OPTIONS.nojs = True #don't decode anything else
                    fixErrors = 0 #don't recurse into this function
                else:
                    time.sleep(0.05)

            if po.poll() == None:
                #process didn't finish
                os.kill(po.pid, signal.SIGKILL)
                if self.OPTIONS.veryverbose:
                    self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, to_write, 'timeout')

            #process finished/killed now

            js_stdout.close()
            js_stdout = open(current_filename + '.stdout', 'rb')
            decoded = js_stdout.read()
            js_stdout.close()

            js_stderr.close()
            js_stderr = open(current_filename + '.stderr', 'rb')
            errors = js_stderr.read()
            js_stderr.close()

            if timeLimitExceededReason:
                self.rooturl[self.url].log(True, 2, '%s %d bytes' % (timeLimitExceededReason, len(decoded)))
                self.rooturl[self.url].setMalicious(2)

            if self.OPTIONS.debug:
                self.rooturl[self.url].dbgobj.add_launch(current_filename)
            else:
                os.remove(current_filename + '.js')
                os.remove(current_filename + '.stdout')
                os.remove(current_filename + '.stderr')


            if errors:
                errors = re.sub('\n\s*$', '', errors) #trailing newlines go away
                errors = re.sub('tmpsha1_[0-9a-f]+\.js:', 'line:', errors) #temp filenames go away
                res = re.search('(Type|Reference)Error: (.*) is (not |un)defined', errors)
                ses = re.search('SyntaxError: illegal character:', errors)
                tes = re.search('TypeError: (.*) is not a function', errors)

                if ses:
                    #if self.OPTIONS.debug:
                    #   print 'illegal chars fixing (%d)' % fixErrors
                    if fixErrors > 0:
                        stripped = cleanChars(to_write) #re.sub('[\x00-\x19\x7f-\xff]','',to_write)
                        newdecoded, runTime = self.decodeJShelper(stripped, fixErrors - 1)
                        if len(newdecoded) >= len(decoded):
                            decoded = newdecoded
                elif res:
                    if fixErrors > 0:
                        if res.group(2).startswith('\\'): #a binary sequence shouldn't occur as a variable name
                            stripped = cleanChars(to_write) #re.sub('[\x00-\x19\x7f-\xff]','',to_write)
                            newdecoded, runTime = self.decodeJShelper(stripped, fixErrors - 1)
                            if len(newdecoded) >= len(decoded):
                                decoded = newdecoded
                        else:
                            self.rooturl[self.url].log(self.OPTIONS.veryverbose, -1, 'undefined variable %s' % (res.group(2)))
                            to_write = 'var %s = 1;\n%s' % (res.group(2), to_write)
                            newdecoded, runTime = self.decodeJShelper(to_write, fixErrors - 1)
                            if len(newdecoded) >= len(decoded):
                                decoded = newdecoded
                elif tes:
                    if fixErrors > 0:
                        #we could try to reconstruct the function by looking in decodings
                        #(same thing with variables)
                        self.rooturl[self.url].log(self.OPTIONS.veryverbose, -1, 'undefined function %s' % (tes.group(1)))
                        to_write = '%s = function (a){}\n%s' % (tes.group(1), to_write)
                        newdecoded, runTime = self.decodeJShelper(to_write, fixErrors - 1)
                        if len(newdecoded) >= len(decoded):
                            decoded = newdecoded
                else:
                    if re.search('SyntaxError: ((illegal|invalid|unexpected end of) XML|syntax error)', errors):
                        pass #self.rooturl[self.url].log(self.OPTIONS.veryverbose,-1,'expecting JavaScript, got HTML')
                    else:
                        self.rooturl[self.url].log(self.OPTIONS.veryverbose, -1, '%s' % re.sub('\n', '\n\terror: ', errors))
        except Exception, e:
            self.rooturl[self.url].log(self.OPTIONS.veryverbose, -1, 'Error: Fatal error in decodeJS: %s (probably you are missing "js" in your path)' % e)
            return '', (time.time() - begin)

        return decoded, (time.time() - begin)

    def build_url_from_path(self, path):
        ''' Build a full URL from possible components/pieces
        urlin is the URL from the HTML
        if the path startswith http, return
        if the path starts with /, return server + path
        if the path is relative, return serverpath+path
        '''
        if path.find('\\/') > -1:
            #fix escaped slashes
            path = re.sub('\\\/', '/', path)

        if path.startswith('http') or path.startswith('//'):
            return re.sub('^[https]*:?//', '', path)
        if path.startswith('hcp:'):
            return path
        if path.startswith('/'):
            if self.url.startswith('/'):
                server = '127.0.0.1'
            else:
                server = re.sub('([^/])/.*$', '\\1', self.url)
            return server + path

        #relative, preserve directory (unless its a file)
        serverpath = re.sub('/[^\/]*$', '/', self.url)
        if self.url.startswith('/'): #its a file
            serverpath = '127.0.0.1/'

        result = serverpath + path
        spaces = result.find(' ')
        if spaces > -1:
            lessthan = result.find('<')
            if -1 < lessthan < spaces:
                result = result[:lessthan]
            else:
                result = result[:spaces]
        return result

    def find_urls(self, data, tcpaddr=[]):
        '''returns JavaScript (if it exists)'''
        jsdata = ''

        if data.find('http:') > -1:
            varurl = re.findall('var[^=]*=[\\\'" ]+(http:[^\'"\n]+)[\\\'"]', data, re.IGNORECASE)
            for i in varurl:
                if i.find('\\/') != -1:
                    i = re.sub('\\\/', '/', i)

                i = re.sub('^[https]+://', '', i)
                self.rooturl[self.url].setChild(i, 'jsvar')
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[javascript variable] URL=%s' % i)

        metarefresh = re.findall('content\s*=\s*[\\\'"]?\d+\s*;\s*url\s*=\s*([^ \r\\\'"]+)', data, re.IGNORECASE)
        for i in metarefresh:
            i = self.build_url_from_path(i)
            self.rooturl[self.url].setChild(i, 'metarefresh')
            self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[meta refresh] URL=%s' % i)

        if data.find('//jsunpack.url') > -1:
            fetch = re.findall('//jsunpack.url (.*?) = (.*?)\n', data)
            #//jsunpack.url setAttribute src = URL
            for desc, i in fetch:
                i = self.build_url_from_path(i)
                self.rooturl[self.url].setChild(i, desc)
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[%s] URL=%s' % (desc, i))

        if data.find(' src=') > -1:
            iframe = re.findall('<(i?frame|embed|script|img|input)[^>]*?[ ]+src=\\\\?[\\\'"]?(.*?)\\\\?[\\\'"> ]', data, re.IGNORECASE)
            for type, i in iframe:
                type = type.lower()

                i = self.build_url_from_path(i)
                if i.startswith('hcp:'):
                    lt = i.find('%3c')
                    LT = i.find('%3C')
                    if lt == -1 and LT > -1:
                        lt = LT
                    if lt > -1:
                        jsdata += re.sub('%([a-fA-F0-9]{2})', lambda mo: convert(mo.group(1)), i[lt:])
                self.rooturl[self.url].setChild(i, type)
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[%s] %s' % (type, i))
        if data.find('<link ') > -1:
            links = re.findall('<(link)[^>]*?[ ]+href=\\\\?[\\\'"]?(.*?)\\\\?[\\\'"> ]', data, re.IGNORECASE)
            for type, i in links:
                type = type.lower()
                i = self.build_url_from_path(i)

                self.rooturl[self.url].setChild(i, type)
        if data.find(' archive=') > -1:
            #Ex. <applet mayscript='true' code='bpac.a.class' archive='bnktjvdpxuko4.jar
            jars = re.findall('<(applet|object)([^>]*)[ ]+archive=\\\\?[\\\'"]?(.*?)\\\\?[\\\'"> ]', data, re.IGNORECASE)
            for type, other_text, i in jars:
                i = self.build_url_from_path(i)
                self.rooturl[self.url].setChild(i, type)

        return jsdata

    def strings(self, data):
        out = []
        readable = re.compile('[\w\s\.\-_=:\$\(\)\\/\'\"\?\&]{4,}')
        matches = readable.findall(data, re.IGNORECASE)
        if matches:
            for match in matches:
                match = match.strip()
                if match is not None:
                    #if re.search(filter,match,re.IGNORECASE) != None:
                    out.append(match)
        return out

    def signature(self, data, level, tcpaddr=[], isPDF=True):
        if self.OPTIONS.debug:
            self.rooturl[self.url].dbgobj.add_timer()

        hits = self.SIGS.process(data, level, isPDF)

        maxImpact = 0
        for id, ref, detect, impact, rulemsg in hits:
            if impact > maxImpact:
                maxImpact = impact
        if maxImpact <= 5:
            hitsAlt = self.SIGSalt.process(re.sub('[^a-zA-Z]', '', data), level, isPDF)
            for h in hitsAlt:
                if not h in hits:
                    hits.append(h)

        for id, ref, detect, impact, rulemsg in hits:
            self.rooturl[self.url].setMalicious(impact)

            alerttxt = []
            for msg in detect:
                if msg.startswith('//shellcode '):
                    self.handle_shellcode(msg, tcpaddr, isPDF)
                else:
                    alerttxt.append(msg)
            if alerttxt:
                detected = []
                for a in alerttxt:
                    a = re.sub('[\x00-\x1f\x7f-\xff]', '.', a)
                    if not a in detected:
                        detected.append(a)

                tmptxt = rulemsg

                if id > 0:
                    tmptxt += '(id %d) ' % id
                if ref:
                    tmptxt += ' ' + ' '.join(ref)
                tmptxt += ' detected %s' % (' '.join(detected))

                self.rooturl[self.url].log(True, impact, tmptxt)
                if impact > 5: #only log malicious
                    self.log_ips()

        if self.OPTIONS.debug:
            self.rooturl[self.url].dbgobj.add_detect(data)

    def log_ips(self):
        if self.OPTIONS.log_ips:
            ip = self.rooturl[self.url].getIP()
            if (not ip in self.ips) and ip != '0.0.0.0':
                if not self.internal_addr(ip):
                    iplog = open(self.OPTIONS.log_ips, 'a')
                    iplog.write('IP\t%s\t%d\n' % (ip, time.mktime(time.localtime())))
                    iplog.close()
                    self.ips.append(ip)

            hostname, dstport = self.hostname_from_url(self.url)
            if hostname and (not hostname in self.ips):
                iplog = open(self.OPTIONS.log_ips, 'a')
                iplog.write('DM\t%s\t%d\n' % (hostname, time.mktime(time.localtime())))
                iplog.close()
                self.ips.append(hostname)

    def handle_shellcode(self, detect, tcpaddr, isPDF=False):
        #hex = re.match('//shellcode .*? = (.*)$', detect)
        hex = re.match('//shellcode (pdf|len) (\d+) .*? = (.*)$', detect)

        #//shellcode len 767 (including any NOPs) payload = %u0A0A%u0A0A%u0A0A%uE1D9%u34D9%u5824%u5858

        if hex:
            source = hex.group(1) #source (pdf|len) currently unused
            sclen = hex.group(2)
            value = hex.group(3)
            value_new = re.sub('%([a-fA-F0-9]{2})', lambda mo: convert(mo.group(1)), value)
            value_new = re.sub('%u([a-fA-F0-9]{2})([a-fA-F0-9]{2})', lambda mo: convert(mo.group(2)) + convert(mo.group(1)), value_new)

            if len(value_new) > 50:
                #only flag shellcode > 50 length
                self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, value_new, 'shellcode')

                impact = 5
                if isPDF:
                    #greater impact because shellcode in PDF files is less likely to have false positives
                    impact = 7
                    self.log_ips()

                self.rooturl[self.url].log(True, impact, 'shellcode of length %d/%s' % (len(value_new), sclen))
                self.rooturl[self.url].setMalicious(impact)

            for t in self.strings(value_new):
                if t.count('.com') + t.count('http'):
                    t = re.sub('^.*?[http]+://', '', t)

                    self.log_ips()
                    self.rooturl[self.url].setChild(t, 'shellcode')
                    self.rooturl[self.url].setMalicious(8)
                    self.rooturl[self.url].log(True, 8, 'shellcode URL=%s' % (t))

            if len(value_new) > 100000:
                pass #out += '\t[info] shellcode overly large, not handling XOR'
            elif not self.OPTIONS.fasteval: # don't perform XOR operation in favor of performance
                for key in range(1, 255):
                    tmp = ''
                    for x in range(0, len(value_new)):
                        tmp += chr(ord(value_new[x]) ^ int(key))
                    results = tmp.count('.com') + tmp.count('http')
                    if results:
                        self.rooturl[self.url].log(True, 10, 'XOR key [shellcode]: %d' % (key))
                        self.log_ips()

                        for t in self.strings(tmp):
                            if t.count('.com') + t.count('http'):
                                t = re.sub('^.*?[http]+://', '', t)

                                self.rooturl[self.url].setChild(t, 'shellcode')
                                self.rooturl[self.url].setMalicious(10)
                                self.rooturl[self.url].log(True, 10, 'shellcode [xor] URL=%s' % (t))

    def dechunk(self, input):
        try:
            data = input
            decoded = ''
            chunk_pos = data.find('\n') + 1
            chunked = int('0x' + data[:chunk_pos], 0)
            while(chunked > 0):
                #decode it!
                decoded += data[chunk_pos:chunked + chunk_pos]
                data = data[chunk_pos + chunked + 2:] #+2 skips \r\n

                chunk_pos = data.find('\n') + 1
                chunked = int('0x' + data[:chunk_pos], 0)
            return decoded
        except:
            return input

    def degzip(self, gzip_data):
        try:
            out = gzip_data #default in case of failure
            datafile = StringIO.StringIO(gzip_data)
            gzfile = gzip.GzipFile(fileobj=datafile)

            out = gzfile.read()
            gzfile.close()
            datafile.close()
        except:
            pass
        return out

    def handleTcpStream(self, tcp):
        ((src, sport), (dst, dport)) = tcp.addr
        if tcp.nids_state == nids.NIDS_JUST_EST:
            #if dport in (80, 8000, 8080):
            tcp.client.collect = 1
            tcp.server.collect = 1

            if self.forceStreams:
                self.streams[tcp.addr] = tcp

        elif tcp.nids_state == nids.NIDS_DATA:
            if self.forceStreams:
                self.streams[tcp.addr] = tcp
            tcp.discard(0)

        elif tcp.nids_state in end_states:
            if self.forceStreams:
                del self.streams[tcp.addr]

            self.handleTcpHelper(tcp)

    def handleTcpHelper(self, tcp):
        ((src, sport), (dst, dport)) = tcp.addr
        toserver = tcp.server.data[:tcp.server.count]
        toclient = tcp.client.data[:tcp.client.count]

        #uris = re.findall("(GET|POST|HEAD)\s+(\S+)", toserver)
        #dom = re.findall("\nHost:\s*(\S+)", toserver)
        #ONLY handle  HTTP/1.1, which assumes Host: header is always available
        lines = toserver.split('\n')
        method = uri = host = referer = ''
        http_request = []
        for line in lines:
            http = re.search('^(GET|POST|HEAD)\s+(\S+)\s+HTTP/\d\.\d', line)
            if http:
                method, uri = http.group(1), http.group(2)

            #header = re.search('^(.*?):\s*(\S+)\s*$',line)
            header = re.search('^(.*?):\s*(.+)\s*$', line)
            if header:
                type, value = header.group(1).lower(), header.group(2)
                value = re.sub('\r', '', value)
                if type == 'host':
                    host = value
                if type == 'referer':
                    referer = canonicalize(value)

            if re.search('^\r?$', line):
                if method:
                    if not host:
                        host = dst

                    fulluri = uri.find(host)
                    if -1 < fulluri <= 8:
                        #replace uri to remove host
                        uri = uri[fulluri + len(host):]

                    get_url = host + uri

                    #Everything has start as its parent (if its a pcap/interface)
                    if not self.start in self.rooturl:
                        self.rooturl[self.start] = urlattr(self.rooturl, self.start)
                    self.rooturl[self.start].setTcpMethod(get_url, tcp.addr, method)

                    http_request.append([method, host, uri, referer])
                    method = uri = host = ''

        #if there is no trailing newline, handle the last request
        if method:
            if not host:
                host = dst
            http_request.append([method, host, uri, referer])
            method = uri = host = ''

        lines = toclient.split('\n')
        code = ''
        http_response = []
        collect = 0
        length = 0
        collected_data = ''
        is_gzipped = is_chunked = 0
        is_redir = ''
        tObj = time.strptime('Tue, 03 Feb 2004 05:06:07 GMT', '%a, %d %b %Y %H:%M:%S %Z')
        lastModified = time.strftime('%m/%d/%Y %H:%M:%S', tObj)

        for line in lines:
            http = re.search('^(.*)HTTP/\d\.\d\s+(\d+)', line)
            #http = re.search('^HTTP/\d\.\d\s+(\d+)', line)
            if http:
                previouscode = code
                previousdata, code = http.group(1), http.group(2)


                if len(previousdata) > 0:
                    collected_data += previousdata

                if collect:
                    if length > 0 and length != len(collected_data):
                        if self.OPTIONS.veryverbose:
                            print '[warning] http response header len = %d, actual len = %d' % (length, len(collected_data))
                    http_response.append([previouscode, collected_data, is_gzipped, is_chunked, is_redir, lastModified])
                    collected_data = ''
                    collect = 0
                    length = 0
                elif previouscode:
                    print '[warning] server response ignored ', tcp.addr
                is_gzipped = is_chunked = 0
                is_redir = ''

            header = re.search('^([^:]*):\s*(.*)\s*$', line)
            if header:
                _value_with_case = header.group(2)
                _value_with_case = re.sub('\r', '', _value_with_case)
                type, value = header.group(1).lower(), _value_with_case.lower()

                if type == 'transfer-encoding':
                    if value.find('chunked') >= 0:
                        is_chunked = 1
                if type == 'content-encoding':
                    if value.find('gzip') >= 0:
                        is_gzipped = 1
                if type == 'content-length':
                    h_len = re.search('^(\d+)', value)
                    length = int(h_len.group(1))

                if type == 'last-modified':
                    #Last-Modified: Fri, 12 Dec 2008 17:11:16 GMT
                    #this is only case where we want the original value, not lowercase
                    try:
                        tObj = time.strptime(_value_with_case, '%a, %d %b %Y %H:%M:%S %Z')
                        lastModified = time.strftime('%m/%d/%Y %H:%M:%S', tObj)
                    except:
                        pass #ignore malformed lastModified values

                if type == 'location':
                    is_redir = value

                if type == 'refresh':
                    #Refresh: 2; URL=http://example
                    vals = value.split('=')
                    if len(vals) == 2:
                        is_redir = vals[1]
            if collect:
                collected_data += line + '\n'

            if re.search('^\r?$', line):
                if code:
                    collect = 1

        #if there is no trailing newline, handle the last response
        if collect and code:
            http_response.append([code, collected_data, is_gzipped, is_chunked, is_redir, lastModified])

        for i in range(0, len(http_response)):
            url = ''
            if i < len(http_request):
                method, host, uri, referer = http_request[i]
                url = canonicalize(host + uri)
            else:
                method = host = uri = referer = ''
                print '[warning] http_request information not available for ', tcp.addr
                continue

            code, data, gzip, chunk, redir, lastModified = http_response[i]
            if chunk:
                data = self.dechunk(data)
            if gzip or data[0:2] == '\x1f\x8b':
                data = self.degzip(data)

            if redir:
                if not redir.startswith('http'):
                    redir = host + redir
                redir = re.sub('^https?://', '', redir)
                redir = canonicalize(redir)

                self.rooturl[url].setChild(redir, 'server_redirect')
            if referer:
                if referer in self.rooturl:
                    self.rooturl[referer].setChild(url, 'refer')

            self.main_decoder(data, url, tcp.addr, lastModified)


    def internal_addr(self, ipin):
        '''returns True if 127.*, or other internal addr'''
        ip = struct.unpack('=L', socket.inet_aton(ipin))[0]

        blocks = [
                    ['127.0.0.0', 8],
                    ['10.0.0.0', 8],
                    ['192.168.0.0', 16],
                    ['172.16.0.0', 12]    ]
        for block, n in blocks:
            ipnet = struct.unpack('=L', socket.inet_aton(block))[0] & (2L << n - 1) - 1
            if ipnet | ip == ipnet:
                return True
        return False

    def hostname_from_url(self, url):
        '''returns [hostname,port]'''
        hostname = '0.0.0.0'
        dstport = 80
        slashIndex = url.find('/')
        if slashIndex > -1:
            hostname = url[:slashIndex] #everything before the first /
        else:
            hostname = url #everything

        if hostname:
            colonIndex = hostname.find(':')
            if colonIndex > -1:
                try:
                    dstport = int(hostname[colonIndex + 1:])
                except:
                    pass #ignore errors in port
                hostname = hostname[:colonIndex]

        return hostname, dstport

    def fetch(self, url):
        if url.startswith('hcp:'):
            return 'Not fetching (hcp url)', ''

        self.url = canonicalize(url)

        #self.rooturl must already have an entry for url
        if not self.url in self.rooturl:
            self.rooturl[self.url] = urlattr(self.rooturl, self.url)

        if self.url.startswith('127.0.0.1'):
            self.rooturl[self.url].malicious = urlattr.DONT_ANALYZE
            return 'Not fetching (local file)', ''

        refer = ''
        for parenturl in self.rooturl:
            for type, child in self.rooturl[parenturl].children:
                if url == child:
                    refer = parenturl

        if (not refer) or refer.startswith(self.OPTIONS.outdir):
            refer = self.defaultReferer
        self.rooturl[self.url].status = '\t(referer=%s)\n' % (refer)
        fname = ''
        try:
            hostname, dstport = self.hostname_from_url(url)

            if self.OPTIONS.proxy and (not self.OPTIONS.currentproxy):
                proxies = self.OPTIONS.proxy.split(',')
                self.OPTIONS.currentproxy = proxies[random.randint(0, len(proxies) - 1)]
                if not self.OPTIONS.quiet:
                    print '[fetch config] random proxy %s' % (self.OPTIONS.currentproxy)

            request = urllib2.Request('http://' + url)
            request.add_header('Referer', 'http://' + refer)
            request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')

            if self.OPTIONS.currentproxy:
                if not self.OPTIONS.quiet:
                    print '[fetch config] currentproxy %s' % (self.OPTIONS.currentproxy)
                proxyHandler = urllib2.ProxyHandler({'http': 'http://%s' % (self.OPTIONS.currentproxy) })
                opener = urllib2.build_opener(proxyHandler)
            else:
                opener = urllib2.build_opener()
            try:
                remote = opener.open(request).read()
            except urllib2.HTTPError, error:
                remote = error.read()

            if len(remote) > 0:
                if len(remote) > 31457280:
                    return 'Not fetching (large file)', ''
                try:
                    fname = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, remote, 'fetch')
                    self.rooturl[self.url].status += '\tsaved %d bytes %s\n' % (len(remote), fname)

                    resolved = socket.gethostbyname(hostname)
                    self.rooturl[self.url].tcpaddr = [['0.0.0.0', 0], [resolved, dstport]]
                except:
                    pass #fail to lookupagain? odd hmm
                self.main_decoder(remote, url)
            else:
                self.rooturl[self.url].malicious = urlattr.ANALYZED

        except Exception, e:
            self.rooturl[self.url].status += '\tfailure: ' + str(e) + '\n'
            self.rooturl[self.url].malicious = urlattr.DONT_ANALYZE

        return self.rooturl[self.url].status, fname

    def main_decoder(self, data, url, tcpaddr=[], lastModified=''):
        url = canonicalize(url)
        self.url = url
        self.lastModified = lastModified
        if not self.url in self.rooturl:
            self.rooturl[self.url] = urlattr(self.rooturl, self.url, tcpaddr) #initialization
        self.rooturl[self.url].setMalicious(urlattr.ANALYZED)
        predecoded = data
        level = 0

        if self.OPTIONS.debug:
            import debug
            if not hasattr(self.rooturl[self.url], 'dbgobj'):
                self.rooturl[self.url].dbgobj = debug.DebugStats(self.url, self.OPTIONS.tmpdir)

            self.rooturl[self.url].dbgobj.start_main()

        #Save all file streams
        if self.OPTIONS.saveallfiles:
            self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, data, 'stream')

        isMZ = False
        if data.startswith('MZ'):
            isMZ = True
            self.rooturl[self.url].filetype = 'MZ'
            self.binExists = True
            if self.OPTIONS.saveallexes:
                sha1exe = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, data, 'executable')
            else:
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[%d] executable file' % (level))


        pdfjs, pdfjs_header = '', ''
        if 0 <= data[0:1024].find('%PDF-') <= 1024:
            isPDF = True
            self.rooturl[self.url].filetype = 'PDF'
            mypdf = pdf.pdf(data, 'PDF-' + self.url)
            if mypdf.is_valid():
                mypdf.parse()
                pdfjs, pdfjs_header = mypdf.getJavaScript()
        else:
            isPDF = False

        swfjs = ''
        if data.startswith('CWS') or data.startswith('FWS'):
            isSWF = True
            self.rooturl[self.url].filetype = 'SWF'

            msgs, urls = swf.swfstream(data)
            for url in urls:
                swfjs_obj = re.search('javascript:(.*)', url, re.I)
                if swfjs_obj:
                    swfjs += swfjs_obj.group(1) + '\n'
                else:
                    #url only
                    multi = re.findall('https?:\/\/([^\s<>\'"]+)', url)
                    if multi:
                        for m in multi:
                            self.rooturl[self.url].setChild(m, 'swfurl')
                    else:
                        #no http
                        if url.startswith('/'):
                            #relative root path
                            firstdir = re.sub('([^/])/.*$', '\\1', self.url)
                            m = firstdir + url
                        else:
                            #relative preserve directory path
                            lastdir = re.sub('/[^\/]*$', '/', self.url)
                            m = lastdir + url
                        self.rooturl[self.url].setChild(m, 'swfurl')
        else:
            isSWF = False

        detect_txt = '' #append all possible decoded data, then run signatures at the end

        if self.OPTIONS.debug:
            self.rooturl[self.url].dbgobj.record_main('init')

        while predecoded and len(predecoded) > 0 and level < 10:
            detect_txt += predecoded

            if isPDF and level > 1:
                #make pdf headers available to all future decodings
                #pdf files are treated as "decodings" therefore level 1 should be ignored for this step
                predecoded = pdfjs_header + predecoded

            self.signature(predecoded, level, tcpaddr, isPDF)
            jsinurls = self.find_urls(predecoded, tcpaddr)

            if self.OPTIONS.nojs: #don't decode anything
                decoded = ''
            elif pdfjs:
                decoded = pdfjs_header + pdfjs
                path = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, decoded, 'decoding')

                if len(pdfjs_header) > 0:
                    self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[decodingLevel=%d] JavaScript in PDF %d bytes, with %d bytes headers' % (level, len(decoded) - len(pdfjs_header), len(pdfjs_header)))
                else:
                    self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[decodingLevel=%d] JavaScript in PDF %d bytes (%s)' % (level, len(decoded), path))
                pdfjs = '' #only once

            elif swfjs:
                decoded = swfjs
                path = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, decoded, 'decoding')
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[decodingLevel=%d] JavaScript in SWF %d bytes (%s)' % (level, len(decoded), path))
                swfjs = '' #only once

            elif self.SIGS.has_javascript(predecoded):
                self.rooturl[self.url].log(self.OPTIONS.verbose, 0, '[decodingLevel=%d] found JavaScript' % (level))
                decoded = self.decodeJS(predecoded, isPDF)

                if decoded and len(decoded) > 0:
                    path = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, decoded, 'decoding')
                    #self.rooturl[self.url].log(self.OPTIONS.verbose,0,'[decodingLevel=%d] decoded %d bytes (%s)' % (level, len(decoded), self.url))#path))

                if self.OPTIONS.debug:
                    self.rooturl[self.url].dbgobj.record_main('decoding')

            elif self.url in self.rooturl and self.rooturl[self.url].type == 'shellcode':
                if predecoded.startswith('MZ'):
                    self.rooturl[self.url].setMalicious(10)
                    sha1exe = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, predecoded, 'incident')
                    self.rooturl[self.url].log(True, 10, 'client download shellcode URL (executable) saved (' + sha1exe + ')')
                else:
                    self.rooturl[self.url].setMalicious(6)
                    sha1exe = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, predecoded, 'attempt')
                    self.rooturl[self.url].log(True, 6, 'client download shellcode URL (non-executable) saved (' + sha1exe + ')')

                try:
                    global ms
                    type = ms.buffer(predecoded)
                    if type:
                        self.rooturl[self.url].log(True, 'download shellcode URL filetype=%s' % (type))
                except:
                    pass # failure in magic library
                decoded = '' # don't do any more decoding

                if self.OPTIONS.debug:
                    self.rooturl[self.url].dbgobj.record_main('shellcode')
            elif isMZ:
                decoded = '' # don't do any more decoding
            else:
                self.rooturl[self.url].log(self.OPTIONS.veryverbose, 0, '[%d] no JavaScript' % (level))
                decoded = '' # don't do any more decoding

            level += 1
            if jsinurls:
                decoded += jsinurls
            predecoded = decoded

        #self.signature(detect_txt,0,tcpaddr,isPDF) #signature accross all content
        #disabled temporarily

        #this way you can match original content + all decodings in one stream
        #level is 0 because we want decodedOnly to still work,
        #you can't write a decodedOnly rule to match across boundaries anyway

        #start output
        if self.rooturl[self.url].malicious > 0:
            #save the original sample
            sha1orig = self.rooturl[self.url].create_sha1file(self.OPTIONS.outdir, data, 'original')
            self.rooturl[self.url].log(self.OPTIONS.verbose, 0, 'file: saved %s to (%s)' % (self.url, sha1orig))

        if self.OPTIONS.decoded:
            if self.OPTIONS.outdir and not os.path.exists(self.OPTIONS.outdir):
                os.mkdir(self.OPTIONS.outdir)

            if os.path.exists(self.OPTIONS.decoded):
                flog = open(self.OPTIONS.decoded, 'a')
            else:
                flog = open(self.OPTIONS.decoded, 'w')

            if flog:
                flog.write(self.rooturl[self.url].tostring('', False)[0])
                flog.close()
                self.rooturl[self.url].seen = {} #reset
            else:
                print 'Error: writing to %s' % (self.OPTIONS.decoded)

        if self.OPTIONS.debug:
            self.rooturl[self.url].dbgobj.finalize_main()

    def run_nids(self, myfile=''):
        if myfile:
            self.forceStreams = True #forceStreams option only applies to pcap files,
            nids.param('filename', myfile)
            nids.init()

        if not self.NIDS_INIALIZED:
            nids.param('scan_num_hosts', 0)
            nids.init()
            nids.chksum_ctl([('0.0.0.0/0', False)])  #this is to exclude checksum verification
                                #which in the case of proxies may cause libnids to miss traffic
            nids.register_tcp(self.handleTcpStream)
            self.NIDS_INIALIZED = True

        try:
            #This is a LIVE-only option soon
            #while 1:
            #    nids.next()

            nids.run()
        except KeyboardInterrupt:
            sys.exit(1)
        except nids.error, e:
            print 'nids/pcap error:', e
        #except Exception, e:
        #   print 'exception:', e
        if self.forceStreams:
            for addr in self.streams: #process unclosed streams
                self.handleTcpHelper(self.streams[addr])

def main():
    global ENABLE_NIDS
    global ENABLE_MAGIC
    socket.setdefaulttimeout(10) #network capable only if -a (--active) parameter specified

    message = '\n\t./jsunpackn.py [fileName]\n\t./jsunpackn.py -i [interfaceName]\n\tjsunpack-network version %s' % (jsunpack.version)

    if not ENABLE_NIDS:
        message += '\n\t[warning] pynids is disabled, while you cannot process pcap files or a network interface, you can still process JavaScript/HTML files\n'

    if not ENABLE_MAGIC:
        message += '\n\t[warning] magic library is disabled\n'

    parser = OptionParser(message)
    parser.add_option('-t', '--timeout', dest='timeout',
        help='limit on number of seconds to evaluate JavaScript', #default=30,
        action='store')
    parser.add_option('-r', '--redoEvalLimit', dest='redoevaltime',
        help='maximium evaluation time to allow processing of alternative version strings', #default=1,
        action='store')
    parser.add_option('-m', '--maxRunTime', dest='maxruntime',
        help='maximum running time (seconds; cumulative total). If exceeded, raise an alert (default: no limit)', default=None,
        action='store')
    parser.add_option('-f', '--fast-evaluation', dest='fasteval',
        help='disables (multiversion HTML,shellcode XOR) to improve performance', #default false
        action='store_true')
    parser.add_option('-u', '--urlFetch', dest='urlfetch',
        help='actively fetch specified URL (for fully active fetch use with -a)', default='',
        action='store')
    parser.add_option('-d', '--destination-directory', dest='outdir',
        help='output directory for all suspicious/malicious content', default='',
        action='store')
    parser.add_option('-c', '--config', dest='configfile',
        help='configuration filepath (default options.config)', default='options.config',
        action='store')
    parser.add_option('-s', '--save-all', dest='saveallfiles',
        help='save ALL original streams/files in output dir', #default=False,
        action='store_true')
    parser.add_option('-e', '--save-exes', dest='saveallexes',
        help='save ALL executable files in output dir', #default=False,
        action='store_true')
    parser.add_option('-a', '--active', dest='active',
        help='actively fetch URLs (only for use with pcap/file/url as input)', #default=False,
        action='store_true')
    parser.add_option('-p', '--proxy', dest='proxy',
        help='use a random proxy from this list (comma separated)',
        action='store')
    parser.add_option('-P', '--currentproxy', dest='currentproxy',
        help='use this proxy and ignore proxy list from --proxy',
        action='store')
    parser.add_option('-q', '--quiet', dest='quiet',
        help='limited output to stdout', #default=False,
        action='store_true')
    parser.add_option('-v', '--verbose', dest='verbose',
        help='verbose mode displays status for all files and decoding stages, without this option reports only detection', #default=False,
        action='store_true')
    parser.add_option('-V', '--very-verbose', dest='veryverbose',
        help='shows all decoding errors (noisy)', #default=False,
        action='store_true')
    parser.add_option('-g', '--graph-urlfile', dest='graphfile',
        help='filename for URL relationship graph, 60 URLs maximium due to library limitations',
        action='store')
    parser.add_option('-i', '--interface', dest='interface',
        help='live capture mode, use at your own risk (example eth0)', default='',
        action='store')
    parser.add_option('-D', '--debug', dest='debug',
        help='(experimental) debugging option, do not delete temporary files', default=False,
        action='store_true')
    parser.add_option('-J', '--javascript-decode-disable', dest='nojs',
        help='(experimental) dont decode anything, if you want to just use the original contents', default=False,
        action='store_true')

    #Disabled/legacy command line options
    '''
    parser.add_option('-T', '--temporary-directory', dest='tmpdir', help='output directory for temporary files (default current directory)', default = '.', action='store')
    parser.add_option('-L', '--log-directory', dest='logdir', help='output directory for log file (default current directory)', default = '.', action='store')
    parser.add_option('-p','--ip-logfile',dest='log_ips', help='optional logfile which appends malicious domains and IP addresses', default='', action='store')
    parser.add_option('-j', '--js-directory', dest='jsdir', help='specify alternate location for pre.js and post.js (default current directory)', default = './', action='store')
    parser.add_option('-Q', '--Quit-file-output', dest='quitfile', help='do not create output files (useful if you import jsunpackn as a python class)', default=False, action='store_true')
    '''

    (options, args) = parser.parse_args()

    #Start config file options
    fileopt = {}

    try:
        config = ConfigParser.RawConfigParser()
        if config.read(options.configfile):
            for path, value in config.items('paths'):
                if value == 'NULL':
                    value = ''
                fileopt[path] = value

            for path, value in config.items('decoding'):
                if value == 'True': value = True
                elif value == 'False': value = False
                fileopt[path] = value
        else:
            print 'Warning: options.config file not found'
    except ConfigParser.NoSectionError, e:
        print 'Fatal Error: invalid options.config file: %s' % (str(e))
        exit()

    for path in fileopt:
        if hasattr(options, path):
            if getattr(options, path):
                pass #cmdline has priority
            else:
                setattr(options, path, fileopt[path])
        else:
            setattr(options, path, fileopt[path])

    #these options must be int values
    options.timeout = int(options.timeout)
    options.redoevaltime = int(options.redoevaltime)
    options.maxruntime = int(options.maxruntime)

    #end config file

    fin = open('rules', 'r')
    if fin:
        options.rules = fin.read()
        fin.close()

    fin = open('rules.ascii', 'r')
    if fin:
        options.rulesAscii = fin.read()
        fin.close()

    if options.htmlparse:
        fin = open(options.htmlparse, 'r')
        if fin:
            options.htmlparseconfig = fin.read()
            fin.close()

    prevRooturl = {}
    if options.interface:
        js = jsunpack('interface', ['', '', ''], options)

    elif options.urlfetch:
        urlattr.verbose = True #shows [nothing found] entries
        options.urlfetch = re.sub('^[https]+://', '', options.urlfetch)

        js = jsunpack(options.urlfetch, ['', '', ''], options)
        prevRooturl = js.rooturl
    elif args:
        for file in args:
            fin = open(file, 'rb')
            mydata = fin.read()
            fin.close()

            js = jsunpack(file, ['', mydata, file], options)

            #js.rooturl[js.start].setMalicious(urlattr.ANALYZED)
    else:
        parser.error('no interfaces or files specified, use -h for help')

    #postprocessing and printing
    #clean history
    for url in js.rooturl:
        js.rooturl[url].seen = {}

    #recursive
    if js.start in js.rooturl:
        tmp = js.rooturl[js.start].tostring('', True)[0]
        if not options.quiet:
            print tmp

    #non-recursive
    if not options.urlfetch:
        #if urlfetch is enabled, then there will be an extra unwanted entry
        #so we can disable it!
        for url in js.rooturl:
            if not options.quiet:
                if len(js.rooturl[url].seen) <= 0:
                    txts = js.rooturl[url].tostring('', False)[0]
                    if txts:
                        print txts

    if options.debug:
        firstCase = 1

        for url in js.rooturl:
            if hasattr(js.rooturl[url], 'dbgobj'):
                if firstCase:
                    print '[debug] TOTAL TIME (%.02f secs js, %.02f secs YARA, %d calls)' % (
                        js.rooturl[url].dbgobj.total_js_time(),
                        js.rooturl[url].dbgobj.total_detect_time(),
                        js.rooturl[url].dbgobj.number_total_launches()
                        )
                    if js.rooturl[url].dbgobj.number_total_launches() > 0:
                        print '[debug] average seconds per call is %.02f\n' % (js.rooturl[url].dbgobj.total_js_time() / js.rooturl[url].dbgobj.number_total_launches())
                    firstCase = 0

                if js.rooturl[url].dbgobj.js_time() > 3:
                    print '[debug] evaluating url %s (%d secs js, %d secs YARA, %d calls)' % (
                        url,
                        js.rooturl[url].dbgobj.js_time(),
                        js.rooturl[url].dbgobj.detect_time(),
                        js.rooturl[url].dbgobj.number_launches()
                        )

    if options.graphfile:
        if options.verbose:
            js.rooturl[js.start].graphall = True
        js.rooturl[js.start].graph(options.graphfile)

    return js #Thanks interns

if __name__ == '__main__':
    main()

