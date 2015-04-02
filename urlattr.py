#!/usr/bin/python
'''
This is a helper class within jsunpack-n
There is no command line usage for this class
'''

from hashlib import sha1
import re
import os

def convert(hex):
    return chr(int('0x' + hex, 0))

def cleanChars(str, replaceWith=''):
    '''
    Input string is stripped of binary characters
        \\x0a is preserved as newline
        \\x20 space and ascii chars
    '''
    return re.sub('[\x00-\x09\x0b-\x19\x7f-\xff]', replaceWith, str)

def canonicalize(input):
    #input is a URL
    #output is a standardized version of the URL
    if os.path.exists(input):
        return input

    output = re.sub('^[https]+:?//', '', input)

    if output.find('/') == -1:
        output += '/'
    output = re.sub('%([a-fA-F0-9]{2})', lambda mo: convert(mo.group(1)), output)

    return output

class urlattr:
    DONT_ANALYZE = -2
    NOT_ANALYZED = -1
    ANALYZED = 0
    verbose = False

    def __init__(self, inrooturl, url, tcpaddr=[['0.0.0.0', 0], ['0.0.0.0', 0]]):
        if self.verbose and url in inrooturl:
            print 'Warning: resetting urlattr %s without checking it (may cause loss of data)' % (url)
            
        self.url = url
        self.tcpaddr = tcpaddr
        self.children = []
        self.method = '' #examples: GET, POST, etc
        self.type = '' #examples: iframe, shellcode, etc. 
        self.filetype = '' #example: PDF, MZ
        self.hasParent = False  #when set to true, it destroys default link 
        self.rooturl = inrooturl
        self.files = [] #decodings, streams, other types of files
        self.status = ''
        
        self.msg = []

        self.malicious = urlattr.NOT_ANALYZED
        self.cumulative_malicious = urlattr.NOT_ANALYZED
        self.seen = {}
        self.showall = False
        self.graphall = False
        #if you add a new field, verify mergeEntries accounts for it

        self.mergeEntries()

    def getIP(self):
        '''returns the ip address of the server'''
        try:
            (srcip, srcport), (dstip, dstport) = self.tcpaddr
            return dstip
        except:
            return '0.0.0.0'

    def setTcpMethod(self, url, tcpaddr, method):
        url = canonicalize(url)
        if not url in self.rooturl:
            self.rooturl[url] = urlattr(self.rooturl, url)

        self.rooturl[url].method = method
        self.rooturl[url].tcpaddr = tcpaddr
        self.setChild(url, 'default')
        
    def mergeEntries(self): 
        #use self.rooturl data to populate
        if self.url in self.rooturl:
            if not self.method:
                self.method = self.rooturl[self.url].method

            if not self.type:
                self.type = self.rooturl[self.url].type
            else:
                if self.type == 'default' and self.rooturl[self.url].type:
                    self.type = self.rooturl[self.url].type

            if self.rooturl[self.url].hasParent:
                self.hasParent = True

            for tuple in self.rooturl[self.url].children:
                if not tuple in self.children:
                    self.children.append(tuple)

            if self.rooturl[self.url].malicious > self.malicious:
                self.malicious = self.rooturl[self.url].malicious
            
            for m in self.rooturl[self.url].msg:
                if not m in self.msg:
                    self.msg.append(m)
    def log(self, printable, severity, msg):
        if not [printable, severity, msg] in self.msg:
            self.msg.append([printable, severity, msg])

    def setMalicious(self, new):
        self.malicious = max(self.malicious, new)
        if self.url in self.rooturl:
            self.rooturl[self.url].malicious = max(self.rooturl[self.url].malicious, new)

    def getChildUrls(self, start, returls=[]):
        #recursive! append to returls parameter
        returls.append(start)

        if start in self.rooturl:
            for t, u in self.rooturl[start].children:
                if not u in returls:
                    returls = self.getChildUrls(u, returls)
        return returls

    def setChild(self, childurl, type):
        '''
            add childurl as a child of self.url
            if childurl already has a type (default, shellcode, jsvar, redirect)
            and it already exists as a child, we'll keep the value previously set
        '''
        if len(childurl) <= 4:
            #make sure length is > 4 (ie, a valid URL)
            return

        childurl = canonicalize(childurl)
        if self.url == childurl:
            return # linking to itself is stupid

        if not childurl in self.rooturl:
            self.rooturl[childurl] = urlattr(self.rooturl, childurl)
            self.rooturl[childurl].type = type

            #preserve method,hasParent,type
            #child_urlattr.mergeEntries()

        if not type == 'default':
            if self.rooturl[childurl].type == 'refer': #prefer other types over refer
                self.rooturl[childurl].type = type 
            elif type == 'refer' and self.rooturl[childurl].type != 'default': #prefer other types over refer
                type = self.rooturl[childurl].type
                
            #this logic determines whether childurl can safely be removed from the root
            #setting the hasParent flag to True will disconnect it

            if len(self.rooturl[childurl].children) <= 0:
                #require that the node has no existing children 
                #to prevent it from being disconnected from the tree
                self.rooturl[childurl].hasParent = True
                self.rooturl[childurl].type = type

            elif not self.url in self.getChildUrls(childurl):
                #looks through self.rooturl[childurl].children, if you find self.url don't destroy the childurl type
                #doing so is bad because it would disconnect the tree
                self.rooturl[childurl].hasParent = True
                self.rooturl[childurl].type = type
            #else:
            #   print 'setChild: ignored %s (whose parent should be %s) because it would disconnect the tree' % (childurl,self.url)

        
        if not self.child_exists(childurl):
            self.rooturl[self.url].children.append([type, childurl])

    def child_exists(self, lookup):
        '''lookup is a url'''
        for t, u in self.rooturl[self.url].children:
            if u == lookup:
                return True
        return False

    def file_exists(self, lookup):
        '''lookup is a sha1hash'''
        for type, hash, data in self.files:
            if lookup == hash:
                return True
        return False
        

    def create_sha1file(self, outdir, data, type='sha1'):
        '''
            outdir is the directory prefix
        '''
        if len(data) <= 0:
            return ''

        shash = sha1(data).hexdigest()
        sha1file = 'undefined'
        sha1file = '%s/%s_%s' % (outdir, type, shash)

        if outdir: #no output directory means don't output anything
            if not os.path.isdir(outdir):
                os.mkdir(outdir)
            if os.path.isdir(outdir):
                ffile = open(sha1file, 'wb')
                ffile.write(data)
                ffile.close()

        #self.files.append([type,shash,data])
        if not self.file_exists(shash):
            self.files.append([type, shash, data])

        return sha1file

        
    def tostring(self, prefix='', recursive=True, parentMalicious=0, path=[]):
        cumulative_malicious = self.malicious

        #if recursive and self.url in self.seen:
        #   #prevent re-analysis
        #   return self.seen[self.url]

        childtxt = ''
        if recursive:
            child_ignored = 0
            for type, child in self.children:
                if self.rooturl[child].hasParent and type == 'default':
                    child_ignored += 1
                elif child in path:
                    #referencing itself can't be good!
                    child_ignored += 1
                else:
                    path.append(child)
                    tmptxt, tmpmal = self.rooturl[child].tostring('\t' + prefix, recursive, max(self.malicious, parentMalicious, path))
                    #childtxt += '\t%s child[%s] using parent[%s]' % (prefix,child.url,self.url)
                    childtxt += tmptxt
                    cumulative_malicious = max(cumulative_malicious, tmpmal)
        intro = ''

        if max(cumulative_malicious, self.malicious, parentMalicious) <= 0 and urlattr.verbose == False:
            return '', cumulative_malicious

        if self.type and (self.type == 'img' or self.type == 'input' or self.type == 'link'):
            #don't expect these to be interesting
            return '', cumulative_malicious

        if self.filetype:
            intro += '[' + self.filetype + '] '
        if self.method:
            intro += self.method + ' '
        if self.type:
            intro += '(' + self.type + ') '

        ip = self.getIP()
        if ip == '0.0.0.0':
            ip = ''
        else:
            ip = '(ipaddr:%s) ' % (ip)

        if self.malicious > 5:
            intro = '[malicious:%d] %s' % (self.malicious, ip) + intro
        elif self.malicious > 0:
            intro = '[suspicious:%d] %s' % (self.malicious, ip) + intro
        else:
        
            extra = ''
            if cumulative_malicious > self.malicious:
                self.cumulative_malicious = cumulative_malicious
                if cumulative_malicious > 5: 
                    extra = ';children=malicious:%d' % (cumulative_malicious)
                elif cumulative_malicious > 0:
                    extra = ';children=suspicious:%d' % (cumulative_malicious)

            if self.malicious == 0:
                intro = '[nothing detected%s] ' % (extra) + intro
            else:
                intro = '[not analyzed%s] ' % (extra) + intro

        intro += self.url
        txt = prefix + '%s\n' % (intro)

        prefix = '\t' + prefix
        #if self.tcpaddr:
        #   txt += prefix + 'requested by %s\n' % (self.tcpaddr[0][0])
        if self.status:
            txt += prefix + 'status: %s\n' % (re.sub('[\t\n]', '', self.status))
        for printable, impact, msg in self.msg:
            msg = re.sub('\n', '\n' + prefix, msg)
            if printable:
                type = ''
                if impact > 5:
                    type = 'malicious'
                elif impact > 0:
                    type = 'suspicious'
                elif impact == 0:
                    type = 'info'
                elif impact < 0:
                    type = 'error'

                txt += prefix + '%s: %s\n' % (type, msg)
        for type, hash, data in self.files:
            txt += prefix + 'file: %s_%s: %d bytes\n' % (type, hash, len(data))

        txt += childtxt
        self.seen[self.url] = [txt, cumulative_malicious]
        return txt, cumulative_malicious

    def graph(self, outfile):
        remaining = 60
        try:
            import yapgvb
            g = yapgvb.Digraph('Analysis of ' + self.url)
        except:
            print 'Unable to import yapgvb, please install python library'

        if os.path.exists(outfile): 
            os.remove(outfile)

        for url in self.rooturl:
            urlstr = url
            if self.rooturl[url].malicious > 5:
                color = yapgvb.colors.red
                urlstr += '\nmalicious'
            elif self.rooturl[url].malicious > 0:
                color = yapgvb.colors.orange
                urlstr += '\nsuspicious'
            else:
                color = 'white'
        
            if max(self.rooturl[url].malicious, self.rooturl[url].cumulative_malicious) > 0 or self.graphall:
                remaining -= 1
                node = g.add_node(url)
                node.label = urlstr
                node.color = color
                node.shape = yapgvb.shapes.box

                for type, child in self.rooturl[url].children:
                    if self.rooturl[child].hasParent and type == 'default':
                        pass 
                    elif max(self.rooturl[url].malicious, self.rooturl[child].cumulative_malicious, self.rooturl[child].malicious) > 0 or self.graphall:
                        cnode = g.add_node(child)
                        cnode.shape = yapgvb.shapes.box
                        cnode.label = child

                        edge = g.add_edge(node, cnode)
                        if not type == 'default':
                            edge.label = type
        if remaining > 0:
            g.layout(yapgvb.engines.dot)
            g.render(outfile)
        else:
            print 'Not graphing "%s" because rooturl used (%d) more nodes than the maximum (60)' % (outfile, -remaining)
