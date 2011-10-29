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

from hashlib import sha1
import datetime
import socket
import jsunpackn

# Error Reporting to /tmp
socket.setdefaulttimeout(10) 

class cmdline_filler:
    options = {
            'timeout':30,
            'redoevaltime':1,
            'maxruntime':0,
            'urlfetch':'',
            'configfile':'options.config',
            'saveallfiles':True, # for pcaps?
            'saveallexes':False,
            'quiet':True,
            'verbose':True,
            'veryverbose':True,
            'graphfile':'',
            'debug':False,
            'active':True,
            'interface':'',
            'nojs':False,
            'log_ips':'./maliciousips.txt',
            'pre':'./pre.js',
            'post':'./post.js',
            'htmlparse':'./htmlparse.config',
            'fasteval':False,
            'proxy': '',
            'currentproxy': '',
        }

    def __init__(self, inhash):
        self.tmpdir = '/tmp' # these temporary files are necessary for decoding, but you can use any path and they will be deleted afterwards
        self.logdir = self.outdir = '' # an empty storage filepath means no directory of output files will be created
        self.decoded = '' #NO decoding logfile, otherwise = self.outdir + '/decoded.log'
        for item in self.options:
            setattr(self, item, self.options[item])

        #Feel free to hard code all your files "rules", "rules.ascii", and "htmlparse.config" in this file instead, only problem is updating them
        fin = open('rules', 'r')
        if fin:
            self.rules = fin.read()
            fin.close()
        fin = open('rules.ascii', 'r')
        if fin:
            self.rulesAscii = fin.read()
            fin.close()
        if self.options['htmlparse']:
            fin = open(self.options['htmlparse'], 'r')
            self.htmlparseconfig = fin.read()
            fin.close()

def main(userdata):
    '''userdata contains the javascript, html, or pdf data to decode'''
    '''if you'd like to do other things with the results, then modify this function'''

    HASH = sha1(str(datetime.datetime.now()) + userdata).hexdigest()
    options = cmdline_filler(HASH)

    root_of_tree = ''   # This can be empty but its sometimes useful to specify a filename here
    url_or_name = '/'    # This can also be empty but if you have the URL, you'd want to set that here
    prevRooturl = {}    # This can also be empty but if you want to decode something with more context its useful to keep state  
    js = jsunpackn.jsunpack(root_of_tree, [url_or_name, userdata, root_of_tree], options, prevRooturl)
    for url in js.rooturl: # set all the state variables for printing
        js.rooturl[url].seen = {}

    results = ''
    for url in [js.start]: #recursive
        print 'The key %s has the following output in recursive mode' % (url)
        results = js.rooturl[url].tostring('', True)[0] + '\n'
        print results
    print 'Note that none of the files are actually created since self.outdir is empty.'

    print 'Instead, you could go through each url and look at the decodings that it creates' 
    for url in js.rooturl:
        print 'Looking at key %s, has %d files and %d messages, that follow:' % (url, len(js.rooturl[url].files), len(js.rooturl[url].msg))
        for type, hash, data in js.rooturl[url].files:
            print 'file              type=%s, hash=%s, data=%d bytes' % (type, hash, len(data))
        for printable, impact, msg in js.rooturl[url].msg:
            print 'output message    printable=%d, impact=%d, msg=%s' % (printable, impact, msg)
    
if __name__ == "__main__":
    main('eval("var a=123;");')
