#!/usr/bin/python
'''
Blake Hartstein v0.1c (beta) pdf parser
Goal: extract all javascript from a pdf file
Revised Goal: extract other malicious parts of a pdf file too
Jan 19, 2010

Command line usage:
$ ./pdf.py [pdf file]
'''
from hashlib import md5
import cStringIO
import Crypto.Cipher.ARC4
import struct
import string
import lzw
import html
import os
import re
import sys
import zlib
import glob
import base64
import binascii

class pdfobj:
    #this class parses single "1 0 obj" up till "endobj" elements
    def __init__(self, keynum, data):
        self.tags = [] #tuples of [key,value]
        self.keynum = keynum
        self.indata = data
        self.tagstream = ''
        self.hiddenTags = 0 #tags containing non-normalized data
        self.children = [] #if this has a script tag, parse children of it
        self.staticScript = '' #for those things not within objects append to this structure

        #special children types
        self.isJS = False #could be a reference (or self contains JS)
        self.isDelayJS = False #for OpenAction
        self.isEmbedded = False #for /EmbeddedFile
        self.isAnnot = False
        self.knownName = '' #related to annots
        self.subj = '' #related to annots
        self.doc_properties = []
        #self.isTitle = False
        #self.isKeywords = False

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

        for index in range(0, len(tag)):
            if state == 'INIT':
                if tag[index] == '/':
                    state = 'TAG'
            elif state == 'TAG':
                if re.match('[a-zA-Z0-9#]', tag[index]):
                    curtag += tag[index]
                elif tag[index] == '/':
                    if curtag:
                        uncleaned_tags.append([state, curtag, '']) # no tag value
                        curtag = ''
                    state = 'TAG' 
                else:
                    state = 'TAGVAL' 
                    curval = ''
            elif state == 'TAGVAL': 
                if tag[index] == '/' and (not tag[index - 1] == '\\\\'): # its a new tag
                    if curtag or curval:
                        uncleaned_tags.append([state, curtag, curval])
                    state = 'TAG'
                    curtag = curval = ''
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
                elif tag[index] == '<' or tag[index] == '>':
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
                    if tag[index - 1] == '\\': #just kidding its not closing 
                        grabMore = 1
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
                    multiline = 1
                    curval += tag[index]
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

            if re.match('^(\\\\[0-9]{3}\s*)+$', tagdata): #ie. need to convert \040 == 0x20
                tagdata = re.sub('\\\\([0-9]{3})', lambda mo: chr(int(mo.group(1), 8)), tagdata)

            tagdata = re.sub('\\\\n', '\n', tagdata)
            tagdata = re.sub('\\\\t', '\t', tagdata)
            tagdata = re.sub('\\\\(.)', '\\1', tagdata)

            if not stream and source == 'TAGVALCLOSED':
                stream = tagdata
                #print 'set stream to %s; %s; %d bytes' % (source, tagtype, len(tagdata))

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

    def parseObject(self):
        #previously this was non-greedy, but js with '>>' does mess things up in that case
        #to solve the problem, do both
        
        #if pdf.DEBUG:
        #    print '\tstarting object len %d' % len(self.indata)
        tags = re.findall('<<(.*)>>[\s\r\n%]*(?:stream[\s\r\n]*(.*?)\n?endstream)?', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if tags:
            for tag, stream in tags:
                gttag = tag.find('>>')
                streamtag = tag.find('stream')

                if 0 < gttag < tag.find('stream'):
                    #this means that there was an improper parsing because the tag shouldn't contain a stream object
                    tags = re.findall('<<(.*?)>>[\s\r\n%]*(?:stream[\s\r\n]*(.*?)\n?endstream)?', self.indata, re.MULTILINE | re.DOTALL | re.IGNORECASE)
                    
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
    def __init__(self, indata, infile):
        self.indata = indata
        self.infile = infile
        self.objects = {} 
        self.pages = []
        self.list_obj = []
        self.encr_key = ''

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
            #print 'found %s with offset %d' % (xref,offset)
        '''

        objs = re.findall('\n?(\d+)\s+(\d+)\s+obj[\s]*(.*?)\s*\n?(endobj|objend)', self.indata, re.MULTILINE | re.DOTALL)
        if objs:
            for obj in objs:
                #fill all objects
                key = obj[0] + ' ' + obj[1]
                if not key in self.list_obj:
                    self.list_obj.append(key)
                self.objects[key] = pdfobj(key, obj[2])

            trailers = re.findall('trailer[\s\n]*<<(.*?)>>', self.indata, re.MULTILINE | re.DOTALL)
            for trailertags in trailers:
                trailerstream = '' #no stream in trailer
                trailerobj = pdfobj('trailer', '') #empty second parameter indicates not to do an object parse
                trailerobj.parseTag(trailertags, trailerstream)
                trailerobj.parseChildren()

                for tag, value in trailerobj.children:
                    if tag == 'Encrypt':
                        encr = {}
                        if value in self.objects:
                            for enc_state, enc_tag, enc_value in self.objects[value].tags:
                                encr[enc_tag] = enc_value

                        ###try: except: for this entire section
                        padding = binascii.unhexlify('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A') 
                        id = ''
                        for iState, isID, idVal in trailerobj.tags:
                            if isID == 'ID':
                                id = re.sub('[^0-9a-fA-F]', '', idVal)
                                if id:
                                    try:
                                        id = binascii.unhexlify(id)
                                    except:
                                        id = ''

                        if 'P' in encr and 'O' in encr:
                            permissions = struct.pack('L', int(encr['P']) & 0xffffffff)
                            
                            enc_in = ('%s%s%s%s' % (padding, encr['O'], permissions, id))
                            #print binascii.hexlify(padding), binascii.hexlify(encr['O']), binascii.hexlify(permissions), binascii.hexlify(id)
                            
                            self.encr_key = md5('%s%s%s%s' % (padding, encr['O'], permissions, id)).digest()[0:5]
                            #print 'encrKey=',self.encr_key
                            cipher = Crypto.Cipher.ARC4.new(self.encr_key)
                            if pdf.DEBUG and 'U' in encr:
                                if encr['U'] == cipher.encrypt(padding):
                                    print 'good pdf encrypt key'
                                else:
                                    print 'bad pdf encrypt key'

            for key in self.list_obj: #sorted(self.objects.keys()):
                #set object options
                if self.encr_key:
                    if self.objects[key].tagstream:
                        self.objects[key].tagstream = self.decryptRC4(self.objects[key].tagstream, key)
                        #print 'trying to decrypt tagstream(%d) on %s' % (len(self.objects[key].tagstream),key)
                        #print 'the input is: ', self.objects[key].tagstream
                        #print 'the output is:', self.decryptRC4(self.objects[key].tagstream,key)

                for kstate, k, kval in self.objects[key].tags:
                    if k == 'OpenAction':
                        self.objects[key].isDelayJS = True
                        for type, childkey in self.objects[key].children:
                            if type == 'OpenAction':
                                if childkey in self.objects:
                                    self.objects[childkey].isDelayJS = True
                                elif pdf.DEBUG:
                                    print 'error: not a valid object for child (%s)' % (childkey)

                    if k == 'JS' or k == 'JavaScript':
                        self.objects[key].isJS = True
                        for type, childkey in self.objects[key].children:
                            if childkey in self.objects and (type == 'JS'):
                                self.objects[childkey].isJS = True
                                self.objects[key].isJS = False
                            #else:
                            #   print 'Warning: missing child %s "%s"' % (type,childkey)

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
                                self.objects[key].staticScript += 'info.%s = String(\'%s\'); this.%s = info.%s;\n' % (k.lower(), pdf.do_hexAscii(value), k.lower(), k.lower())
                                self.objects[key].staticScript += 'app.doc.%s = String(\'%s\');\n' % (k.lower(), pdf.do_hexAscii(value))
                    
                for kstate, k, kval in self.objects[key].tags:
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
                    
                #for k, kval in self.objects[key].tags:
                #    if k == 'ObjStm': #object stream, embedded object will be full of tags
                #        if pdf.DEBUG:
                #            print 'objstm results in %s' % (self.objects[key].tagstream)
                    
                self.objects[key].tagstream = pdf.applyFilter(self.objects[key].tagstream)
                if pdf.DEBUG and self.objects[key].tagstream.startswith('MZ'):
                    print 'PDF file has embedded MZ file'
        else:
            print 'Fatal error: pdf has no objects in ' + self.infile

    def decryptRC4(self, data, key):
        '''
            Input: data is the data to decrypt, key is the obj information of the form '5 0'
            Assumptions: self.encr_key is set
            Output: returns string of decrypted data
        '''
        try:
            obj, rev = key.split(' ')
            decrypt_key = md5(self.encr_key + struct.pack('L', int(obj))[0:3] + struct.pack('L', int(rev))[0:2]).digest()[0:10]
            cipher = Crypto.Cipher.ARC4.new(decrypt_key)
            return cipher.decrypt(data)
        except:
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
        for jskey in self.list_obj: #(self.objects.keys()):
            if self.objects[jskey].staticScript:
                out += self.objects[jskey].staticScript

            if self.objects[jskey].tagstream:
                value = self.objects[jskey].tagstream
                value = re.sub('\'', '\\x27', value)
                if self.objects[jskey].isAnnot:
                    out += 'var zzza = []; if(zzzannot.length > 0){ zzza=zzzannot.pop(); } zzza.push({subject:\'%s\'}); zzzannot.push(zzza);\n' % (value) #getAnnots
                    if self.objects[jskey].knownName:
                        if self.objects[jskey].subj:
                            subj = self.objects[jskey].subj
                        else:
                            subj = value
                        subj = re.sub('[\x00-\x1f\x7f-\xff]', '', subj)
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
        for jskey in (self.objects.keys()):
            if self.objects[jskey].isEmbedded:
                #found embedded file
                #run htmlparsing
                parsed_header, parsed_data = self.objects[jskey].hparser.htmlparse(self.objects[jskey].tagstream)
                parsed_data = re.sub('&lt;', '<', parsed_data)
                parsed_data = parsed_header + parsed_data
                self.objects[jskey].tagstream = parsed_data

                if pdf.DEBUG:
                    if len(parsed_data) > 0:
                        print 'parsed JavaScript (xml, in pdf) %d bytes' % (len(parsed_data))
                    else:
                        num_stored = 0
                        for format, store_data in self.objects[jskey].hparser.storage:
                            fout = open('%s.stored_item_%02d' % (self.infile, num_stored), 'wb')
                            try: 
                                decoded_store_data = base64.b64decode(store_data)
                                fout.write(decoded_store_data)
                                print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(decoded_store_data), self.infile, num_stored)
                            except:
                                fout.write(store_data)
                                print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(store_data), self.infile, num_stored)

                            fout.close()
                            num_stored += 1

                '''
                #look for tiff image fields (OKAY, this isn't REALLY JavaScript!)
                for format,store_data in self.objects[jskey].hparser.storage:
                    try:
                        image_data = base64.b64decode(store_data)
                        out += '//shellcode pdf %d PDFtiff = ' % len(store_data)
                        for c in image_data:
                            out += '%%%02x' % ord(c)
                        out += '\n'
                    except:
                        if pdf.DEBUG:
                            print 'failed to base64.b64decode an EmbeddedFile'
                '''
                    

            if self.objects[jskey].isDelayJS: #do this first incase the tag has /OpenAction /JS (funct())
                if pdf.DEBUG:
                    print 'Found JavaScript (delayed) in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                delayout += self.objects[jskey].tagstream
            elif self.objects[jskey].isJS:
                if pdf.DEBUG:
                    print 'Found JavaScript in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                out += self.objects[jskey].tagstream

            if pdf.DEBUG:
                if self.objects[jskey].isJS or self.objects[jskey].isDelayJS:
                    print '\tchildren ' + str(self.objects[jskey].children) 
                    print '\ttags ' + str(self.objects[jskey].tags)
                    print '\tindata = ' + re.sub('[\n\x00-\x19\x7f-\xff]', '', self.objects[jskey].indata)[:100]

        if len(out + delayout) <= 0:
            #Basically if we don't find ANY JavaScript, then we can parse the other elements
            for jskey in self.objects.keys():
                sloppy = re.search('function |var ', self.objects[jskey].tagstream)
                if sloppy:
                    out += self.objects[jskey].tagstream
                    if pdf.DEBUG:
                        print 'Sloppy PDF parsing found %d bytes of JavaScript' % (len(out))

        return re.sub('\\x00', '', out + delayout), headersjs

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
    pdf.DEBUG = True
    html.debug = True
    for file in files:
        data = ''
        if os.path.exists(file):
            fin = open(file, 'r')
            data = fin.read()
            fin.close()

        mypdf = pdf(data, file)
        if mypdf.is_valid():
            print 'parsing %s' % file
            mypdf.parse()
            decoded, decoded_headers = mypdf.getJavaScript()

            if len(decoded) > 0:
                decoded = decoded_headers + decoded
                fout = open(file + '.out', 'w')
                if fout:
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
