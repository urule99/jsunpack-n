#!/usr/bin/python
'''
Blake Hartstein v0.1c (beta) pdf parser
Goal: extract all javascript from a pdf file
Revised Goal: extract other malicious parts of a pdf file too
Jan 19, 2010

Command line usage:
$ ./pdf.py [pdf file]

Updated 2013-04-11 Thanks for the contributions from David Dorsey of visiblerisk.com
'''
from hashlib import md5, sha256
import base64
import binascii
import cStringIO
import Crypto.Cipher.ARC4 as ARC4
import Crypto.Cipher.AES as AES
import html
import glob
import lzw
import os
import re
import string
import struct
import sys
import xml.dom.minidom
import zlib


class pdfobj:
    #this class parses single "1 0 obj" up till "endobj" elements
    def __init__(self, keynum, data):
        self.tags = [] #tuples of [key,value]
        self.keynum = keynum
        self.indata = data
        self.tagstream = ''
        self.tagstreamError = False
        self.tagstreamChanged = False
        self.hiddenTags = 0 #tags containing non-normalized data
        self.children = [] #if this has a script tag, parse children of it
        self.staticScript = '' #for those things not within objects append to this structure

        #special children types
        self.isJS = False #could be a reference (or self contains JS)
        self.isDelayJS = False #for OpenAction
        self.isEmbedded = False #for /EmbeddedFile
        self.isAnnot = False
        self.isObjStm = []
        self.isXFA = False
        self.isEncrypt = False
        self.isFromObjStream = False
        self.knownName = '' #related to annots
        self.subj = '' #related to annots
        self.doc_properties = []
        #self.isTitle = False
        #self.isKeywords = False
        self.xfaChildren = []

        pdfparseconfig = '''
!define rawSCRIPT   ;%s
!parse  script      *   rawSCRIPT:contents
!parse  imagefield1 *   to_python:contents
!filter script      <[/]?script[^>]*>|<!--|//-->
!filter *           ^javascript:\s*|^return\s+
        '''
        #xfa:contenttype

        self.hparser = html.Parser(pdfparseconfig)
        if self.indata:
            self.parseObject()

    def __repr__(self):
        out = 'pdfobj %s\n' % (self.keynum)
        if self.children:
            out += '\tchildren %s\n' % (str(self.children))
        if self.isJS:
            out += '\tisJS'
        if self.isAnnot:
            out += '\tisAnnot'
        for property in self.doc_properties:
            out += '\tis%s' % property
        if self.isDelayJS:
            out += '\tisDelayJS'
        return out

    def parseTag(self, tag, stream):
        '''
            Input:  tag is the contents of /Tag1 value1 /Tag2 value2
                    stream is (optional) contents between stream and endstream
            Output: self.tags and self.tagstream
            If stream is not set, then we should set it before it gets assigned to tagstream
        '''
        state = 'INIT'
        curtag = ''
        curval = ''
        multiline = 0 # for tracking multiline in TAGVALCLOSED state
        uncleaned_tags = [] #output of statemachine
        numParenOpen = 0
        isBracketClosed = True
        for index in range(0, len(tag)):
            #if self.keynum == '1 0':
                #print state, index, hex(index), hex(ord(tag[index])), curtag, len(curval), numParenOpen, isBracketClosed
            if state == 'INIT':
                isBracketClosed = True
                if tag[index] == '/':
                    state = 'TAG'
            elif state == 'TAG':
                isBracketClosed = True
                if re.match('[a-zA-Z0-9#]', tag[index]):
                    curtag += tag[index]
                elif tag[index] == '/':
                    if curtag:
                        uncleaned_tags.append([state, curtag, '']) # no tag value
                        curtag = ''
                    state = 'TAG'
                elif tag[index] == '(':
                    state = 'TAGVALCLOSED'
                    numParenOpen = 0
                    multiline = 0
                    curval = '' # ignore the (, for the most part
                elif tag[index] == '[': # start of an array... probably
                    state = 'TAGVAL'
                    isBracketClosed = False
                    curval = '['
                elif tag[index] == '\n':
                    state = 'TAG'
                else:
                    state = 'TAGVAL' 
                    curval = ''
            elif state == 'TAGVAL': 
                # Weird cases with arrays
                if tag[index] == '/' and (not tag[index - 1] == '\\\\') and \
                    ((curval and curval[0] == '[' and isBracketClosed) or  \
                    (not curval) or (curval and curval[0] != '[')):
                    # a new open bracket and we are not in the middle of a bracket
                     # or there is bracket here, but we ignore this one
                    if curtag or curval:
                        uncleaned_tags.append([state, curtag, curval])
                    state = 'TAG'
                    curtag = curval = ''
                elif curval and curval[0] == '[' and tag[index] == ']':  # finished array
                    curval += tag[index]
                    isBracketClosed = True
                elif tag[index] == '(':
                    #what do we do with curval? toss it
                    if re.match('^[\s\[\]\(\)<>]*$', curval): # look for any characters that indicate this isn't a TAGVALCLOSED
                        state = 'TAGVALCLOSED'
                        multiline = 0

                        if len(curval) > 0:
                            #print '\ttossed out %d characters (%s) because we entered TAGVALCLOSED state' % (len(curval),curval)
                            curval = ''
                    else: #keep processing?
                        curval += tag[index]
                elif tag[index] == '[' and curtag == 'XFA': # coming up on an array listing the XFA objects
                    isBracketClosed = False
                    state = 'TAGVALCLOSED'
                # Normally ignore these, but they are useful when parsing the ID in the trailer
                elif (tag[index] == '<' or tag[index] == '>') and self.keynum != 'trailer':
                    pass
                elif tag[index] == ' ' and curval == '':
                    pass #already empty
                else:
                    curval += tag[index] 
            elif state == 'TAGVALCLOSED':
                #in this state we know that the code started with (... therefore we can't end until we see )
                #the code could also have enclosed ( chars; therefore, this algorithm is greedy
                grabMore = 0 # if grabMore is set to 1, it means the tag isn't closing yet
                if tag[index] == ')': #possible closing tag
                    if tag[index - 1] == '\\' and tag[index-2] != '\\' or \
                        (tag[index-1] == '\\' and tag[index-2] == '\\' and tag[index-3] == '\\') or \
                        ((curtag == 'JS' or curtag == 'JavaScript') and numParenOpen > 0) or \
                        (curtag == 'XFA' and not isBracketClosed): # we are in the middle of a JS string or an XFA array 
                        grabMore = 1
                        numParenOpen-=1
                    elif multiline: #tricky cases
                        #either a newline or "(" character leads us here.

                        #IGNORE THESE
                        #if re.match('^\)\s*($|\n\s*([^\)\s])',tag[index:]):
                        #    #yep its closing time
                        #    #this regex ensures there isn't another following close tag
                        #res = re.match('^(.*)\)  $',tag[index:])

                        
                        if index + 1 < len(tag):
                            indexParen = tag[index + 1:].find(')')
                            #indexNewL = tag[index+1:].find('\n')
                            if indexParen > -1: # and (indexNewL == -1 or indexNewL > indexParen):
                                if not re.match('^\s*\/[A-Za-z0-9]+\s*\(', tag[index + 1:]):
                                    grabMore = 1        

                    if grabMore:
                        curval += tag[index]
                    else: #ok ok, its simply closing
                        uncleaned_tags.append([state, curtag, curval])
                        state = 'INIT'
                        #print '%s (TAGVALCLOSED), length=%d bytes with %d/%d completed (around %s)' % (curtag, len(curval),index,len(tag), tag[index-20:index+20])
                        curtag = curval = ''
                elif tag[index] == '(': #tag[index] == '\n' 
                    numParenOpen += 1
                    curval += tag[index]
                elif tag[index] == ']' and curtag != 'JS' and not isBracketClosed: # can have ]s inside JS strings...
                    isBracketClosed = True
                else:
                    curval += tag[index]
            else:
                print 'invalid state in parseTag: %s' % state
        if curtag: #an ending tag with NO final separator
            uncleaned_tags.append(['ENDTAG', curtag, curval])

        #clean uncleaned_tags and put in self.tags instead
        for source, tagtype, tagdata in uncleaned_tags:
            newtagtype = pdfobj.fixPound(tagtype)
            if newtagtype != tagtype:
                self.hiddenTags += 1
                tagtype = newtagtype

            #newlines in tagtype? ONLY for state != TAGVALCLOSED
            if source != 'TAGVALCLOSED':
                #its okay to replace newlines, spaces, tabs here
                tagdata = re.sub('[\s\r\n]+', ' ', tagdata)

            # You can have octal further in the string, but that can sometimes cause problems
            # so if there is a problem, just back out and use the original
            if re.search('([^\\\\]\\\\[0-9]{3}\s*)+$', tagdata): #ie. need to convert \040 == 0x20
                original = tagdata
                try:
                    tagdata = re.sub('\\\\([0-9]{3})', lambda mo: chr(int(mo.group(1), 8)), tagdata)
                except:
                    tagdata = original
            
            # to my dismay, there are lot of tags to unescape
            unescaped_tagdata = ''
            backslash = False
            for d in tagdata:
                if backslash:
                    backslash = False
                    if d == 'b':
                        unescaped_tagdata += '\b'
                    elif d == 'f':
                        unescaped_tagdata += '\f'
                    elif d == 'n':
                        unescaped_tagdata += '\n'
                    elif d == 'r':
                        unescaped_tagdata += '\r'
                    elif d == 's':
                        unescaped_tagdata += 's' # this one is weird, I know
                    elif d == 't':
                        unescaped_tagdata += '\t'
                    elif d in ('(', ')', '\\'):
                        unescaped_tagdata += d
                elif d == '\\':
                    backslash = True
                else:
                    unescaped_tagdata += d

            tagdata = unescaped_tagdata
                #print 'set stream to %s; %s; %d bytes' % (source, tagtype, len(tagdata))

            # Only really want the JavaScript, and then only when it's not in a unicode format 
            if not stream and \
                (source == 'TAGVALCLOSED' or source == 'ENDTAG') and \
                (tagtype == 'JS' or tagtype == 'JavaScript') and \
                len(tagdata) > 2 and tagdata[0:2] != '\xfe\xff': 
                stream = tagdata
            self.tags.append([source, tagtype, tagdata])
        self.tagstream = stream

        if pdf.DEBUG:
            print 'obj %s: ' % (self.keynum)
            for source, tagtype, tagdata in self.tags:
                
                tagtxt = '\ttag %s' % re.sub('\n', '', tagtype)  
                if len(tagdata) > 30: 
                    tagtxt += ' = [data %d bytes]' % len(tagdata) 
                elif tagdata:
                    tagtxt += ' = '
                    for c in tagdata:
                        if c in string.printable and c != '\n':
                            tagtxt += c
                        else:
                            tagtxt += '\\x%02x' % (ord(c))
                print '%-50s (%s)' % (tagtxt, source) 
                #end 

    def parseChildren(self):
        '''
            Input: self.tags (must be populated)
            Output: self.children
        '''
        for state, k, kval in self.tags:
            hasRef = re.search('^(\d+)\s+(\d+)\s+R', kval)
            if hasRef:
                objkey = hasRef.group(1) + ' ' + hasRef.group(2)
                self.children.append([k, objkey])
            if k == 'XFA':
                kids = re.findall('(\d+\s+\d+)\s+R', kval)
                for kid in kids:
                    self.xfaChildren.append([k, kid])

    def parseObject(self):
        #previously this was non-greedy, but js with '>>' does mess things up in that case
        #to solve the problem, do both
        
        #if pdf.DEBUG:
        #    print '\tstarting object len %d' % len(self.indata)
        tags = re.findall('<<(.*)>>[\s\r\n%]*(?:stream[\r\n]*(.*?)[\r\n]*endstream)?', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if tags:
            for tag, stream in tags:
                gttag = tag.find('>>')
                streamtag = tag.find('stream')
                endstreamTagEnd = self.indata.rfind('endstream')
                endstreamTagBegin = self.indata.find('endstream')
                #
                # This means that there was an improper parsing because the tag shouldn't contain a stream object
                if endstreamTagEnd != -1 and 0 < gttag < streamtag:
                    # do this in case the word stream is in the tag data somewhere...
                    streamLocation = re.search('>>[\s\r\n%]*stream?', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)

                    streamStart = self.indata.find('stream', streamLocation.start())
                    streamMatch = re.search('stream[\s\r\n]*(.*?)[\r\n]*endstream', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    streamData = ''
                    # Only search to start of stream, a compressed stream can have >> in it, and that will through off the regex
                    tagMatch = re.search('<<(.*)>>', self.indata[0:streamStart], re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    if tagMatch and streamMatch:
                        streamData = streamMatch.group(1)
                        tag = tagMatch.group(1)
                        tags = [(tag, streamData)]
                #
                # This checks if the word endstream happens inside the stream
                if endstreamTagBegin != -1 and endstreamTagBegin != endstreamTagEnd:
                    streamLocation = re.search('>>[\s\r\n%]*stream?', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    streamStart = self.indata.find('stream', streamLocation.start())
                    streamMatch = re.search('stream[\s\r\n]*(.*?)[\r\n]*endstream$', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    tagMatch = re.search('<<(.*)>>', self.indata[0:streamStart], re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    streamData = ''
                    if streamMatch and tagMatch:
                        streamData = streamMatch.group(1)
                        tag = tagMatch.group(1)
                        tags = [(tag, streamData)]

        if not tags: #Error parsing object!
            return

        for tag, stream in tags:
            self.parseTag(tag, stream)
            self.parseChildren()

    @staticmethod
    def fixPound(i):
        #returns '#3a' substituted with ':', etc
        #strips newlines, '[', and ']' characters
        #this allows indexing in arrays

        i = re.sub('[\[\]\n]', '', i)
        i = re.sub('<<$', '', i)
        return re.sub('#([a-fA-F0-9]{2})', lambda mo: chr(int('0x' + mo.group(1), 0)), i)
        
    @staticmethod
    def lzwdecode(input):
        try:
            return ''.join(lzw.LZWDecoder(cStringIO.StringIO(input)).run())
        except:
            return input

    @staticmethod
    def rldecode(input):
        output = ''
        index = 0
        try:
            key_len = ord(input[index])

            while key_len != 0x80:
                index += 1
                if key_len & 0x80:
                    output += input[index] * (256 - key_len + 1)
                    index += 1
                else:
                    output += input[index:index + key_len + 1]
                    index += key_len + 1
                key_len = ord(input[index])
        except: 
            return input
        return output

    @staticmethod
    def ascii85(input):
        outdata = ''
        input = re.sub('\s', '', input)
        input = re.sub('^<~', '', input)
        input = re.sub('~>$', '', input)

        for i in range(0, len(input), 5):
            bytes = input[i:i + 5]
            fraglen = len(bytes)
            if bytes[0] == 'z':
                pass #ignore
            if bytes[0] == 'y':
                pass #ignore
            if i + 5 >= len(input):
                #data not divisible by 5
                bytes = input[i:]
                fraglen = len(bytes)
                if fraglen > 1:
                    bytes += 'vvv'

            total = 0
            shift = 85 * 85 * 85 * 85
            for c in bytes:
                total += shift * (ord(c) - 33)
                shift /= 85

            if fraglen > 1:
                outdata += chr((total >> 24) % 256)
                if fraglen > 2:
                    outdata += chr((total >> 16) % 256)
                    if fraglen > 3:
                        outdata += chr((total >> 8) % 256)
                        if fraglen > 4:
                            outdata += chr((total) % 256)
        return outdata

class pdf:
    DEBUG = 0
    def __init__(self, indata, infile, password= ''):
        self.indata = indata
        self.infile = infile
        self.objects = {} 
        self.pages = []
        self.list_obj = []
        self.jsObjects = []
        self.encryptKey = ''
        self.encryptKeyValid = False
        self.encryptObject = {}
        self.encryptPassword = password
        self.xfaObjects = []

    def parse(self):

        '''
        #parsing xref tables
        xrefs = re.findall('xref\s*\n\d+\s+(\d+)\s*\n((\d+\s+\d+\s+[fn]\s*\n)+)\s*trailer\s*\n',self.indata)#.*?startxref\s*\n(\d+)\s*\n\s*%%EOF\s*',self.indata)
        for entries, table,junk in xrefs:
            entries = int(entries)
            print 'entries=',entries
            lines = table.split('\n')
            for line in lines:
                valid = re.match('\s*(\d+)\s+(\d+)\s+[fn]\s*',line)
                if valid:
                    offset,zero = int(valid.group(1)), int(valid.group(2))
                    print 'line = ', offset, zero
            #offset = int(offset)
        '''

        objs = re.findall('\n?(\d+)\s+(\d+)\s+obj[\s]*(.*?)\s*\n?(endobj|objend)', self.indata, re.MULTILINE | re.DOTALL)
        if objs:
            for obj in objs:
                #fill all objects
                key = obj[0] + ' ' + obj[1]
                if not key in self.list_obj:
                    self.list_obj.append(key)
                else: # There are cases with the two objects have the same number, because PDFs are awesome that way
                    key = key + ' dup'
                    self.list_obj.append(key)

                self.objects[key] = pdfobj(key, obj[2])

            trailers = re.findall('(trailer[\s\r\n]*<<(.*?)>>)', self.indata, re.MULTILINE | re.DOTALL)
            for trailertags in trailers:
                trailerData = trailertags[1]
                #
                # Check for a dictionary inside the trailer
                #
                isDict = trailerData.find("<<")
                if isDict != -1:
                    offset = self.indata.find(trailertags[0])
                    trailerData = self.extractTrailerData(offset)

                trailerstream = '' #no stream in trailer
                trailerobj = pdfobj('trailer', '') #empty second parameter indicates not to do an object parse
                trailerobj.parseTag(trailerData, trailerstream)
                trailerobj.parseChildren()
                key = 'trailer'
                if not key in self.list_obj:
                    self.list_obj.append(key)
                else: # There are cases with the two objects have the same number, because PDFs are awesome that way
                    key = key + ' dup'
                    self.list_obj.append(key)
                self.objects[key] = trailerobj
                for tag, value in trailerobj.children:
                    # If there is an encrypt object, it should be specified in the trailer
                    # (in practice, that's not always the case... *sigh*)
                    if tag == 'Encrypt' and not self.encryptKeyValid:
                        # Make sure the encrypt object is actually there
                        if value in self.objects:
                            self.objects[value].isEncrypt = True
                            self.encryptObject = self.populateEncryptObject(self.objects[value])

                        fileId = ''
                        for state, tag, val in trailerobj.tags:
                            if tag == 'ID':
                                ids = re.findall('<([\d\w]*)>', val)
                                # Just in case the ID has something I'm not expecting
                                if ids:
                                    try:
                                        fileId = binascii.unhexlify(ids[0])
                                    except:
                                        fileId = ''
                                else:
                                    fileId = val

                        # yay for default passwords
                        padding = binascii.unhexlify('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A')
                        # limit of 16 characters
                        passwd = (self.encryptPassword + padding)[0:32]
                        self.encryptKey = self.computeEncryptKey(self.encryptObject, passwd, fileId)
                        self.encryptKeyValid = self.validateEncryptKey(self.encryptKey, padding, fileId, self.encryptObject)
                        break

            # but wait, sometimes the encrypt object is not specified in the trailer, yet sometimes another
            # object has it in it, so search for it now
            if not self.encryptKeyValid:
                encryptObjectKey = ''
                fileId  = ''
                for key in self.list_obj:
                    for kstate, k, kval in self.objects[key].tags:
                        if k == 'Encrypt':
                            for childType, childKey in self.objects[key].children:
                                if childType == 'Encrypt':
                                    self.objects[childKey].isEncrypt = True
                                    encryptObjectKey = childKey
                                    break
                        if k == 'ID':
                            fileId = ''
                            ids = re.findall('\[([\d\w]*)\]', kval)
                            if ids:
                                firstId = ids[0]
                                # for some reason it's there twice...
                                firstId = firstId[0:len(firstId)/2]
                                try:
                                    fileId = binascii.unhexlify(firstId)
                                except:
                                    fileId = ''

                    if encryptObjectKey and fileId:
                        break

                if encryptObjectKey and fileId: # we found it
                    self.encryptObject = self.populateEncryptObject(self.objects[encryptObjectKey])
                    padding = binascii.unhexlify('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A')
                    # limit of 32 characters here
                    passwd = (self.encryptPassword + padding)[0:32]
                    self.encryptKey = self.computeEncryptKey(self.encryptObject, passwd, fileId)
                    if self.encryptObject['V'] == 5 and self.encryptKey != '\xca\x1e\xb0' and 'Perms' in self.encryptObject:
                        aes = AES.new(self.encryptKey, AES.MODE_ECB)
                        decryptedPerms = aes.decrypt(self.encryptObject['Perms'])
                        if decryptedPerms[0:4] == self.encryptObject['P'][0:4] and decryptedPerms[9:12] == 'adb':
                            self.encryptKeyValid = True
                    else:
                        self.encryptKeyValid = self.validateEncryptKey(self.encryptKey, padding, fileId, self.encryptObject)

            for key in self.list_obj: #sorted(self.objects.keys()):
                #set object options
                if self.encryptKey and self.encryptKeyValid:
                    if self.objects[key].tagstream and not self.objects[key].isEncrypt and not self.objects[key].isFromObjStream:
                        if self.encryptObject['algorithm'] == 'RC4':
                            self.objects[key].tagstream = self.decryptRC4(self.objects[key].tagstream, key)
                        elif self.encryptObject['algorithm'] == 'AES':
                            self.objects[key].tagstream = self.decryptAES(self.objects[key].tagstream, key)

                        self.objects[key].tagstreamModified = True

                for kstate, k, kval in self.objects[key].tags:
                    if k == 'OpenAction':
                        # sometimes OpenAction is an array, so check for that
                        if not kval or kval[0] != '[':
                            self.objects[key].isDelayJS = True
                            for childType, childKey in self.objects[key].children:
                                if childType == 'OpenAction' and childKey in self.objects:
                                    self.objects[childKey].isDelayJS = False # This isn't the JS, the children have it
                                    for cState, cType, cValue in self.objects[childKey].tags:
                                        if cType in ['JavaScript', 'JS']:
                                            self.objects[childKey].isDelayJS = True
                                elif pdf.DEBUG:
                                    print 'error: not a valid object for child (%s)' % (childKey)


                    if k  in ['JavaScript', 'JS']:
                        self.objects[key].isJS = True
                        foundChildJs = False
                        for childType, childKey in self.objects[key].children: # Is the JS with the children?
                            if childKey in self.objects and childType in ['JS', 'JavaScript']:
                                self.objects[childKey].isJS = True
                                self.objects[key].isJS = False
                                if childKey not in self.jsObjects:
                                    self.jsObjects.append(childKey)
                                foundChildJs = True

                        if not foundChildJs: # JS is here
                            if key not in self.jsObjects:
                                self.jsObjects.append(key)

                    if k == 'XFA':
                        self.objects[key].isXFA = True

                    if k == 'NM':
                        self.objects[key].knownName = kval

                    if k == 'Subj':
                        self.objects[key].subj = kval

                    if k == 'EmbeddedFile':
                        self.objects[key].isEmbedded = True

                    if k == 'Annot':
                        #since JavaScript can call getAnnots() we must populate these entries now
                        #don't handle /Annots (precursory tag), children will contain Subj element

                        self.objects[key].isAnnot = True
                        for type, childkey in self.objects[key].children:
                            if childkey in self.objects and (type == 'Subj'):
                                self.objects[childkey].isAnnot = True

                    if k == 'Page':
                        hasContents = False
                        for type, childkey in self.objects[key].children:
                            if type == 'Contents':
                                self.pages.append(childkey)
                                hasContents = True
                        if not hasContents:
                            self.pages.append(key)

                    #populate pdfobj's doc_properties with those that exist
                    enum_properties = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate', 'plot']

                    if k in enum_properties:
                            value = kval
                            value = re.sub('[\xff\xfe\x00]', '', value)
                            isReference = re.match('^\s*\d+\s+\d+\s+R\s*$', value)
                            if isReference:
                                validReference = False
                                for type, childkey in self.objects[key].children:
                                    if childkey in self.objects and (type == k):
                                        validReference = True
                                        self.objects[childkey].doc_properties.append(k.lower())
                                if not validReference:
                                    if pdf.DEBUG:
                                        print '[warning] possible invalid reference in %s' % (k)
                                    self.objects[key].doc_properties.append(k.lower())
                            else:
                                #not a reference, use the direct value
                                value = re.sub('\'', '\\x27', value)
                                self.objects[key].staticScript += 'info.%s = String(\'%s\');\n' % (k.lower(), pdf.do_hexAscii(value))
                                self.objects[key].staticScript += 'this.%s = info.%s;\n' % (k.lower(), k.lower())
                                self.objects[key].staticScript += 'info.%s = info.%s;\n' % (k, k.lower())
                                self.objects[key].staticScript += 'app.doc.%s = info.%s;\n' % (k.lower(), k.lower())
                                self.objects[key].staticScript += 'app.doc.%s = info.%s;\n' % (k, k.lower())
                                
                                if k == 'CreationDate':
                                    self.objects[key].staticScript += 'app.doc.creationDate = info.creationdate;\n'
                                    self.objects[key].staticScript += 'info.creationDate = info.creationdate;\n'

                                if key not in self.jsObjects:
                                    self.jsObjects.append(key)

                for kstate, k, kval in self.objects[key].tags:
                    # Multiple filters, sometimes pound issues, throws off the decode, so handle it here
                    if k == 'Filter':
                        kval = pdfobj.fixPound(kval)
                        filters = re.findall('/(\w+)', kval)
                        if filters:
                            for filter in filters:
                                if filter == 'FlateDecode' or filter == 'Fl': 
                                    try:
                                        self.objects[key].tagstream = zlib.decompress(self.objects[key].tagstream)
                                    except zlib.error, msg:
                                        if pdf.DEBUG:
                                            print 'failed to decompress object %s (inlen %d)' % (key, len(self.objects[key].tagstream))
                                            print self.objects[key].tagstream
                                        self.objects[key].tagstream = '' #failed to decompress

                                if filter == 'ASCIIHexDecode' or filter == 'AHx':
                                    result = ''
                                    counter = 0
                                    self.objects[key].tagstream = re.sub('[^a-fA-F0-9]+', '', self.objects[key].tagstream)
                                    for i in range(0, len(self.objects[key].tagstream), 2):
                                        result += chr(int('0x' + self.objects[key].tagstream[i:i + 2], 0))
                                    self.objects[key].tagstream = result
                                if filter == 'ASCII85Decode' or filter == 'A85':
                                    self.objects[key].tagstream = pdfobj.ascii85(self.objects[key].tagstream)
                                if filter == 'LZWDecode' or filter == 'LZW':
                                    self.objects[key].tagstream = pdfobj.lzwdecode(self.objects[key].tagstream)
                                if filter == 'RunLengthDecode' or filter == 'RL':
                                    self.objects[key].tagstream = pdfobj.rldecode(self.objects[key].tagstream)

                    if k == 'FlateDecode' or k == 'Fl': 
                        try:
                            self.objects[key].tagstream = zlib.decompress(self.objects[key].tagstream)
                        except zlib.error, msg:
                            if pdf.DEBUG:
                                print 'failed to decompress object %s (inlen %d)' % (key, len(self.objects[key].tagstream))
                                print self.objects[key].tagstream
                            self.objects[key].tagstream = '' #failed to decompress

                    if k == 'ASCIIHexDecode' or k == 'AHx':
                        result = ''
                        counter = 0
                        self.objects[key].tagstream = re.sub('[^a-fA-F0-9]+', '', self.objects[key].tagstream)
                        for i in range(0, len(self.objects[key].tagstream), 2):
                            result += chr(int('0x' + self.objects[key].tagstream[i:i + 2], 0))
                        self.objects[key].tagstream = result
                    if k == 'ASCII85Decode' or k == 'A85':
                        self.objects[key].tagstream = pdfobj.ascii85(self.objects[key].tagstream)
                    if k == 'LZWDecode' or k == 'LZW':
                        self.objects[key].tagstream = pdfobj.lzwdecode(self.objects[key].tagstream)
                    if k == 'RunLengthDecode' or k == 'RL':
                        self.objects[key].tagstream = pdfobj.rldecode(self.objects[key].tagstream)

                # Check for Object Streams, but only if we don't have an error with tagstream
                if not self.objects[key].tagstreamError:
                    objectStreamData = ''
                    objectStreamN = 0
                    objectStreamFirst = 0
                    for kstate, k, kval in self.objects[key].tags:
                        if k == 'ObjStm':
                            objectStreamData = self.objects[key].tagstream
                        if k == 'N':
                            # just in case
                            try:
                                objectStreamN = int(kval)
                            except:
                                pass
                        if k == 'First':
                            # ...
                            try:
                                objectStreamFirst = int(kval)
                            except:
                                pass

                    if objectStreamData != '' and objectStreamN != 0 and objectStreamFirst != 0:
                        self.parseObjectStream(objectStreamData, objectStreamN, objectStreamFirst)

                self.objects[key].tagstream = pdf.applyFilter(self.objects[key].tagstream)
                if pdf.DEBUG and self.objects[key].tagstream.startswith('MZ'):
                    print 'PDF file has embedded MZ file'
        else:
            print 'Fatal error: pdf has no objects in ' + self.infile

    def populateEncryptObject(self, encryptObject):
        e = {}

        e['V'] = 0
        e['R'] = 0
        e['O'] = ''
        e['U'] = ''

        for state, tag, value in encryptObject.tags:
            # Multiple lengths, referring to different things, take the bigger one, that *should* be right
            if tag == 'Length' and 'Length' in e:
                if int(value) > int(e[tag]):
                    e[tag] = value
                continue
            e[tag] = value

        e['KeyLength'] = 5

        if 'AESV2' in e or 'AESV3' in e:
            e['algorithm'] = 'AES'
        else:
            e['algorithm'] = 'RC4'
 
        if 'EncryptMetadata' in e:
            if e['EncryptMetadata'].lower() == 'false':
                e['EncryptMetadata'] = False
        else:
            e['EncryptMetadata'] = True

        if 'V' in e:
            e['V'] = int(e['V'])

        if e['V'] >= 2 and 'Length' in e:
            e['KeyLength'] = int(e['Length'])/8

        if 'R' in e:
            e['R'] = int(e['R'])

        if e['R'] <= 4 and len(e['O']) > 32:
            e['O'] = binascii.unhexlify(e['O'].strip())

        if e['R'] <= 4 and len(e['U']) > 32:
            e['U'] = binascii.unhexlify(e['U'].strip())

        if 'P' in e:
            e['P'] = struct.pack('L', int(e['P']) & 0xffffffff)

        return e

    def computeEncryptKey(self, encryptObject, password, fileId):
        if encryptObject['R'] <= 4:
            h = md5()
            h.update(password)
            h.update(encryptObject['O'])
            h.update(encryptObject['P'][0:4])
            h.update(fileId)
            if encryptObject['R'] == 4 and not encryptObject['encryptMetadata']:
                h.update("\xff\xff\xff\xff")
            key = h.digest()[0:encryptObject['KeyLength']]
            if encryptObject['R'] >= 3:
                for i in range(50):
                    key = md5(key[0:encryptObject['KeyLength']])
                key = key[0:encryptObject['KeyLength']]

            return key

        elif encryptObject['R'] == 5:
            userKey = sha256(encryptObject['U'][32:40]).digest()
            if userKey == encryptObject['U'][0:32]: # success!
                almostKey = sha256(encryptObject['U'][40:48]).digest()
                aes = AES.new(almostKey, AES.MODE_CBC, '\x00'*16)
                theKey = aes.decrypt(encryptObject['UE'])
                return theKey

            #
            # Ok, then check the owner password
            #
            ownerSha = sha256()
            ownerSha.update(encryptObject['O'][32:40])
            ownerSha.update(encryptObject['U'][0:48])
            ownerHash = ownerSha.digest()
            if ownerHash == encryptObject['O'][0:32]:
                almostHash = shas256()
                almostHash.update(encryptObject['O'][40:48])
                almostHash.update(encryptObject['U'][0:48])
                almostKey = almostHash.digest()
                aes = AES.new(almostKey, AES.MODE_CBC, '\x00'*16)
                theKey = aes.decrypt(encryptObject['OE'])
                return theKey
        else:
            print "No good", encryptObject['R']

        return '\xca\x1e\xb0'

    def validateEncryptKey(self, key, password, fileId, encryptObject):
        if encryptObject['R'] == 2:
            rc4 = ARC4.new(key)
            passwordEncrypted = rc4.encrypt(password)
            if encryptObject['U'] == passwordEncrypted:
                return True
        elif encryptObject['R'] >= 3:
            m = md5()
            m.update(password)
            m.update(fileId)
            cHash = m.digest()
            rc4 = ARC4.new(key)
            dHash = rc4.encrypt(cHash)
            for i in range(1, 20):
                newKey = ''
                for k in key:
                    newKey += chr(ord(k) ^ i)
                stepE = ARC4.new(key)
                dHash = stepE.encrypt(dHash)

            if dHash == encryptObject['U'][0:16]:
                return True
        else:
            print "No good", encryptObject['R']

        return False

    def parseObjectStream(self, data, n, first):
        intPairs = re.findall('(\d+) +(\d+)', data[0:first])
        
        i = 1
        for p in intPairs:
            key = str(p[0]) + " 0"

            startOffset = first + int(p[1])
            if i == n:
                endOffset = None
            else:
                endOffset = first + int(intPairs[i][1])

            objData = data[startOffset:endOffset]

            if not key in self.list_obj:
                self.list_obj.append(key)
            else:
                key = key + ' dup'
                self.list_obj.append(key)

            self.objects[key] = pdfobj(key, objData)
            self.objects[key].isFromObjStream = True
            i+=1

        return

    def extractTrailerData(self, trailerStart):
        dictionaries = 0
        trailerEnd = trailerStart
        firstDictionary = False
        while dictionaries != 0 or not firstDictionary:
            d = self.indata[trailerEnd:trailerEnd+2]
            if d == '<<':
                firstDictionary = True
                dictionaries+=1
                trailerEnd+=2
                continue
            elif d == '>>':
                dictionaries-=1
                trailerEnd+=2
                continue
            elif d == '':
                break

            trailerEnd+=1

        trailer = self.indata[trailerStart:trailerEnd]
        return trailer

    def decryptRC4(self, data, key):
        '''
            Input: data is the data to decrypt, key is the obj information of the form '5 0'
            Assumptions: self.encryptKey is set
            Output: returns string of decrypted data
        '''
        try:
            obj, rev = key.split(' ')

            keyLength = self.encryptObject['KeyLength'] + 5
            if keyLength > 16:
                keyLength = 16

            decrypt_key = md5(self.encryptKey + struct.pack('L', int(obj))[0:3] + struct.pack('L', int(rev))[0:2]).digest()[0:keyLength]
            cipher = ARC4.new(decrypt_key)
            return cipher.decrypt(data)
        except:
            return ''

    def decryptAES(self, aesData, objectKey):
        if self.encryptObject['V'] <= 4:
            try:
                obj, rev = objectKey.split(' ')
                keyLength = self.encryptObject['KeyLength'] + 5
                if keyLength > 16:
                    keyLength = 16
                m = md5()
                m.update(self.encryptKey)
                m.update(struct.pack('L', int(obj))[0:3])
                m.update(struct.pack('L', int(rev))[0:2])
                m.update('\x73\x41\x6c\x54')
                aesKey = m.digest()[0:keyLength]
                iv = aesData[0:16]
                aes = AES.new(aesKey, AES.MODE_CBC, iv)
                padSize = 16 - (len(aesData)%16)
                pad = "C" * padSize
                data = aes.decrypt(aesData[16:] + pad)[0:(padSize*-1)]
                return data
            except Exception as e:
                return ''
        else:
            try:
                iv = aesData[0:16]
                aes = AES.new(self.encryptKey, AES.MODE_CBC, iv)
                padSize = 16 - (len(aesData)%16)
                pad = "C" * padSize
                data = aes.decrypt(aesData[16:] + pad)[0:(padSize*-1)]
                return data
            except Exception as e:
                return ''


    def is_valid(self):
        if 0 <= self.indata[0:1024].find('%PDF-') <= 1024:
            return True
        return False
        
    def __repr__(self):
        if not self.is_valid():
            return 'Invalid PDF file "%s"' % (self.infile)
        out = 'PDF file %s has %d obj items\n' % (self.infile, len(self.objects))
        for obj in sorted(self.objects.keys()):
            out += str(self.objects[obj]) + '\n'

        return out

    def getJavaScript(self):
        out = ''
        pagenow = 0
        sloppyFlag = False
        for jskey in self.jsObjects:
            if self.objects[jskey].tagstreamError:
                continue

            if self.objects[jskey].staticScript:
                out += self.objects[jskey].staticScript

            if self.objects[jskey].tagstream:
                value = self.objects[jskey].tagstream
                value = re.sub('\'', '\\x27', value)
                # Sometimes there is just weird data there (or unicode), maybe getting rid of it helps
                # (like below)
                value = re.sub('[\x00-\x1f\x7f-\xff]', '', value)

                if self.objects[jskey].isAnnot:
                    out += 'var zzza = []; if(zzzannot.length > 0){ zzza=zzzannot.pop(); } zzza.push({subject:\'%s\'}); zzzannot.push(zzza);\n' % (value) #getAnnots
                    if self.objects[jskey].knownName:
                        if self.objects[jskey].subj:
                            subj = self.objects[jskey].subj
                        else:
                            subj = value
                        subj = re.sub('[\x00-\x1f\x7f-\xff]', '', subj) # <- below
                        out += 'zzzannot2["%s"] = {subject:\'%s\'};\n' % (self.objects[jskey].knownName, subj) #getAnnot
                for property in self.objects[jskey].doc_properties:
                    out += 'info.%s = String(\'%s\'); this.%s = info.%s;\n' % (property, pdf.do_hexAscii(value), property, property)
        for page in self.pages:
            if page in self.objects:
                lines = self.objects[page].tagstream.split('\n')
                out += 'c = []; '
                for line in lines:
                    textBE = re.findall('BT[^(]*\(([^)]+)\)[^)]*?ET', line)
                    for hexdata in textBE:
                        words = hexdata.split(' ')
                        for word in words:
                            out += 'c.push("%s"); ' % (pdf.do_hexAscii(word))
                out += 'zzzpages.push(c); this.numPages = zzzpages.length;\n'
                pagenow += 1
        if out:
            out += '\n//jsunpack End PDF headers\n'

        headersjs = out #split value into 2 return values [js, header_js]       
        out = ''

        delayout = ''
        for jskey in self.jsObjects:
            if self.objects[jskey].tagstreamError:
                continue

            #if self.objects[jskey].isEmbedded:
            #    #found embedded file
            #    #run htmlparsing
            #    parsed_header, parsed_data = self.objects[jskey].hparser.htmlparse(self.objects[jskey].tagstream)
            #    parsed_data = re.sub('&lt;', '<', parsed_data)
            #    parsed_data = parsed_header + parsed_data
            #    self.objects[jskey].tagstream = parsed_data

            #    if pdf.DEBUG:
            #        if len(parsed_data) > 0:
            #            print 'parsed JavaScript (xml, in pdf) %d bytes' % (len(parsed_data))
            #        else:
            #            num_stored = 0
            #            for format, store_data in self.objects[jskey].hparser.storage:
            #                fout = open('%s.stored_item_%02d' % (self.infile, num_stored), 'wb')
            #                try: 
            #                    decoded_store_data = base64.b64decode(store_data)
            #                    fout.write(decoded_store_data)
            #                    print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(decoded_store_data), self.infile, num_stored)
            #                except:
            #                    fout.write(store_data)
            #                    print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(store_data), self.infile, num_stored)

            #                fout.close()
            #                num_stored += 1
            #    '''
            #    '''
            #    #look for tiff image fields (OKAY, this isn't REALLY JavaScript!)
            #    for format,store_data in self.objects[jskey].hparser.storage:
            #        try:
            #            image_data = base64.b64decode(store_data)
            #            out += '//shellcode pdf %d PDFtiff = ' % len(store_data)
            #            for c in image_data:
            #                out += '%%%02x' % ord(c)
            #            out += '\n'
            #        except:
            #            if pdf.DEBUG:
            #                print 'failed to base64.b64decode an EmbeddedFile'
            #    '''
                    

            # only do it if no encryption or it was decrypted
            if self.encryptKey == '' or self.encryptKeyValid == True:
                if self.objects[jskey].isDelayJS: #do this first incase the tag has /OpenAction /JS (funct())
                    if pdf.DEBUG:
                        print 'Found JavaScript (delayed) in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                    delayout += self.objects[jskey].tagstream
                elif self.objects[jskey].isJS:
                    if pdf.DEBUG:
                        print 'Found JavaScript in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                    #if jskey == '84 0':
                    #    print self.objects[jskey].tagstream

                    if len(self.objects[jskey].tagstream) > 4 and self.objects[jskey].tagstream[3] != '\x00':
                        out += self.objects[jskey].tagstream
                    else:
                        tempJs = re.sub(r'([^\x00])\x0a', r'\1', self.objects[jskey].tagstream)
                        tempJs = re.sub(r'([^\x00])\x0d', r'\1', tempJs)
                        tempJs = re.sub('([\x00-\x08\x0b\x0c\x0e-\x1f])', '', tempJs)
                        tempJs = re.sub('([\x80-\xff])', 'C', tempJs)
                        out += tempJs

                if pdf.DEBUG:
                    if self.objects[jskey].isJS or self.objects[jskey].isDelayJS:
                        print '\tchildren ' + str(self.objects[jskey].children) 
                        print '\ttags ' + str(self.objects[jskey].tags)
                        print '\tindata = ' + re.sub('[\n\x00-\x19\x7f-\xff]', '', self.objects[jskey].indata)[:100]

        for key in self.list_obj:
            if self.objects[key].isXFA and (self.encryptKey == '' or self.encryptKeyValid):
                xfaData = ''
                for xfaType, xfaKey in self.objects[key].xfaChildren:
                    xfaData += self.objects[xfaKey].tagstream

                # gets rid of some crap.  But unicode will probably cause problems down the road
                xfaData = re.sub('([\x00-\x08\x0b\x0c\x0e-\x1f])', '', xfaData)
                xfaData = re.sub('([\x80-\xff])', 'C', xfaData)
                try:
                    doc = xml.dom.minidom.parseString(xfaData)
                except Exception as e:
                    print "drat", str(e)
                    continue

                scriptElements = doc.getElementsByTagNameNS("*", "script")
                if not scriptElements:
                    continue

                for script in scriptElements:
                    if script.getAttribute('contentType') != 'application/x-javascript' or not script.childNodes:
                        continue
                    
                    js = script.childNodes[0].data
                    # maybe?
                    if type(js) == unicode:
                        js = unicode(js).encode('utf-8')

                    dataForJs = ''
                    jsName = script.parentNode.parentNode.getAttribute('name')
                    if type(jsName) == unicode:
                        jsName = unicode(jsName).encode('utf-8')

                    dataElements = doc.getElementsByTagName(jsName)
                    if dataElements and dataElements[0].childNodes and dataElements[0].childNodes[0].nodeType == xml.dom.minidom.Node.TEXT_NODE:
                        dataForJs = dataElements[0].childNodes[0].data

                    xfaJs = ''
                    if jsName:
                        xfaJs += jsName + "=this;\n"
                        xfaJs += 'var rawValue = "' + dataForJs + '";\n';

                    xfaJs += js + '\n'
                    if jsName:
                        xfaJs += 'print("<rawValue>" + ' + jsName + '.rawValue + "</rawValue>");\n'

                    out += xfaJs

        if len(out + delayout) <= 0:
            #Basically if we don't find ANY JavaScript, then we can parse the other elements
            for jskey in self.objects.keys():
                sloppy = re.search('function |var ', self.objects[jskey].tagstream)
                if sloppy:
                    sloppyFlag = True
                    out += self.objects[jskey].tagstream
                    if pdf.DEBUG:
                        print 'Sloppy PDF parsing found %d bytes of JavaScript' % (len(out))

        
        return re.sub('[\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff]', '', out + delayout), headersjs, sloppyFlag

    @staticmethod
    def do_hexAscii(input):
        return re.sub('([^a-zA-Z0-9])', lambda m: '\\x%02x' % ord(m.group(1)), input)

    @staticmethod
    def applyFilter(input):
        if len(input) > 10000000:
            return input

        for i in range(0, len(input)):
            c = ord(input[i])
            if 0 < c < 0x19 or 0x7f < c < 0xff or input[i] in ' \n\r':
                pass #cut beginning non-ascii characters
            else:
                input = input[i:]
                break

        input = input[::-1] #reversed
        for i in range(0, len(input)):
            c = ord(input[i])

            if 0 < c < 0x19 or 0x7f < c < 0xff or input[i] in ' \n\r':
                pass  #cut trailing non-ascii characters
            else:
                input = input[i:]
                break
        output = input[::-1]

        #output = re.sub('^[\x00-\x19\x7f-\xff\n\s]*[\x00-\x19\x7f-\xff]','',input) #look for starting non-ascii characters
        #output = re.sub('[\x00-\x19\x7f-\xff\s]+$','',output) #look for trailing non-ascii characters
        return output

def main(files):
    pdf.DEBUG = False
    html.debug = True
    for file in files:
        data = ''
        if os.path.exists(file):
            fin = open(file, 'r')
            data = fin.read()
            fin.close()

        mypdf = pdf(data, file, '')
        if mypdf.is_valid():
            print 'parsing %s' % file
            mypdf.parse()
            decoded, decoded_headers, sloppyFlag = mypdf.getJavaScript()

            if len(decoded) > 0:
                decoded = decoded_headers + decoded
                fout = open(file + '.out', 'w')
                if fout:
                    if sloppyFlag:
                        print "SLOPPY"

                    print 'Wrote JavaScript (%d bytes -- %d headers / %d code) to file %s' % (len(decoded), len(decoded_headers), len(decoded) - len(decoded_headers), file + '.out') 
                    fout.write(decoded)
                    fout.close()
            else:
                print 'Didnt decode any JavaScript within PDF file'
        else:
            print('warn: ignoring non-pdf file ' + file)
    

if __name__ == '__main__':
    for i in sys.argv[1:]:
        main(glob.glob(i))
