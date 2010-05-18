#!/usr/bin/python
'''
Blake Hartstein v0.1c (beta) pdf parser
Goal: extract all javascript from a pdf file
Revised Goal: extract other malicious parts of a pdf file too
Jan 19, 2010

Command line usage:
$ ./pdf.py [pdf file]
'''
import os, re, sys, zlib, glob, base64
import lzw, html
import cStringIO

class pdfobj:
    #this class parses single "1 0 obj" up till "endobj" elements
    def __init__(self,keynum,data):
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
    def parseObject(self):
        #previously this was non-greedy, but js with '>>' does mess things up in that case
        #to solve the problem, do both
        
        #if pdf.DEBUG:
        #    print '\tstarting object len %d' % len(self.indata)
        tags = re.findall('<<(.*)>>[\s\r\n%]*(?:stream[\s\r\n]*(.*?)\n?endstream)?',self.indata,re.MULTILINE|re.DOTALL)
        if tags:
            for tag,stream in tags:
                gttag = tag.find('>>')
                streamtag = tag.find('stream')

                if 0 < gttag < tag.find('stream'):
                    #this means that there was an improper parsing because the tag shouldn't contain a stream object
                    tags = re.findall('<<(.*?)>>[\s\r\n%]*(?:stream[\s\r\n]*(.*?)\n?endstream)?',self.indata,re.MULTILINE|re.DOTALL)
                    
        if not tags: #Error parsing object!
            return

        for tag,stream in tags:
            tag = re.sub('[\s\r\n]+',' ',tag)
            tagarray = tag.split('/')

            #if tagarray elements contain legitimate '/' characters, we need to rejoin them back together
            multiline = '' #This should remain null, UNLESS we find multiline javascript
            multiline_key = ''
            for t in tagarray:
                if not multiline: #new (no previous state)
                    #both oneliner and multiliner are looking for JavaScript
                    valid_oneliner = re.match('^([^\s(]+)\s*[(](.*[^\\\\])[)]\s*$',t)
                    valid_multiliner = re.search('^(\S+)\s+[(](.*)$',t)
                    if valid_oneliner:
                        orig_tagkey,tagvalue = valid_oneliner.group(1), valid_oneliner.group(2)

                        tagkey = pdfobj.fixPound(orig_tagkey)
                        if tagkey != orig_tagkey:
                            self.hiddenTags += 1

                        if re.match('^(\\\\[0-9]{3}\s*)+$',tagvalue): #ie. need to convert \040 == 0x20
                            tagvalue = re.sub('\\\\([0-9]{3})', lambda mo: chr(int(mo.group(1),8)), tagvalue)
                        tagvalue = re.sub('\\\\n','\n', tagvalue)
                        tagvalue = re.sub('\\\\t','\t', tagvalue)
                        tagvalue = re.sub('\\\\(.)','\\1', tagvalue)

                        self.tags.append([tagkey,tagvalue])
                        if not stream:
                            #try decompress first?
                            stream = tagvalue
                            #if pdf.DEBUG: print 'set stream = %s' % tagvalue
                    elif valid_multiliner:
                        #cant use '/' as a delimiter
                        #stream contains escaped code
                        multiline = t
                        orig_multiline_key = valid_multiliner.group(1)
                        multiline_key = pdfobj.fixPound(orig_multiline_key) 
                        if orig_multiline_key != multiline_key:
                            self.hiddenTags += 1
                        
                        self.tags.append([multiline_key,valid_multiliner.group(2)])
                    else: # not a JavaScript tag
                        simpleTag = re.search('^(\S+)[\s<>]*(.*?)[\s<>]*$',t)
                        if simpleTag:
                            orig_tagkey = simpleTag.group(1)
                            tagkey = pdfobj.fixPound(orig_tagkey)
                            if orig_tagkey != tagkey:
                                self.hiddenTags += 1
                            
                            self.tags.append([tagkey,simpleTag.group(2)])
                        
                else: #multiline continuing 
                    
                    k, kval = self.tags[len(self.tags)-1]
                    self.tags[len(self.tags)-1] = [k, kval + '/' + t]
            if multiline: #multiline ending
                #find the close to the void via a ')' character, it could also be followed by /S /JavaScript, other tags
                k, tmpstream = self.tags[len(self.tags)-1]
                tmpstream = re.sub('([^\\\\])[)]\s*(\/[a-zA-Z]*\s*)*$','\\1', tmpstream)
                if re.match('^(\\\\[0-9]{3}\s*)+$',tmpstream): #ie. need to convert \040 == 0x20
                    tmpstream = re.sub('\\\\([0-9]{3})', lambda mo: chr(int(mo.group(1),8)), tmpstream)
                tmpstream = re.sub('\\\\n','\n', tmpstream)
                tmpstream = re.sub('\\\\t','\t', tmpstream)
                tmpstream = re.sub('\\\\(.)','\\1', tmpstream)
                self.tags[len(self.tags)-1] = [k,tmpstream]

                
                #Trailing unwanted tags
                #tags[fixPound(voidkey)] = re.sub('\/(S|JavaScript)\s*$','', tags[fixPound(voidkey)])
                #tags[fixPound(voidkey)] = re.sub('\/(S|JavaScript)\s*$','', tags[fixPound(voidkey)])
                stream = tmpstream

            self.tagstream = stream
    @staticmethod
    def fixPound(i):
        #returns '#3a' substituted with ':', etc
        #strips newlines, '[', and ']' characters
        #this allows indexing in arrays

        i = re.sub('[\[\]\n]','',i)
        i = re.sub('<<$','',i)
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
                    output += input[index:index+key_len + 1]
                    index += key_len + 1
                key_len = ord(input[index])
        except: 
            return input
        return output

    @staticmethod
    def ascii85(input):
        outdata = ''
        input = re.sub('\s','',input)
        input = re.sub('^<~','',input)
        input = re.sub('~>$','',input)

        for i in range(0,len(input),5):
            bytes = input[i:i+5]
            fraglen = len(bytes)
            if bytes[0] == 'z':
                pass #ignore
            if bytes[0] == 'y':
                pass #ignore
            if i+5 >= len(input):
                #data not divisible by 5
                bytes = input[i:]
                fraglen = len(bytes)
                if fraglen>1:
                    bytes += 'vvv'

            total = 0
            shift = 85*85*85*85
            for c in bytes:
                total += shift*(ord(c)-33)
                shift /= 85

            if fraglen > 1:
                outdata += chr((total>>24) % 256)
                if fraglen > 2:
                    outdata += chr((total>>16) % 256)
                    if fraglen > 3:
                        outdata += chr((total>>8) % 256)
                        if fraglen > 4:
                            outdata += chr((total) % 256)
        return outdata

class pdf:
    DEBUG = 0
    def __init__(self,indata,infile):
        self.indata = indata
        self.infile = infile
        self.objects = {} 
        self.pages = []
        self.list_obj = []

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

        objs = re.findall('\n?(\d+)\s+(\d+)\s+obj[\s]*(.*?)\s*\n?(endobj|objend)',self.indata,re.MULTILINE|re.DOTALL)
        if objs:
            for obj in objs:
                #fill all objects
                key = obj[0] + ' ' + obj[1]
                self.list_obj.append(key)
                self.objects[key] = pdfobj(key,obj[2])

            for key in self.list_obj: #sorted(self.objects.keys()):
                #set object options

                for k,kval in self.objects[key].tags:
                    hasRef = re.search('^(\d+)\s+(\d+)\s+R',kval)
                    if hasRef:
                        objkey = hasRef.group(1)+' '+ hasRef.group(2)
                        self.objects[key].children.append([k,objkey])

                for k, kval in self.objects[key].tags:
                    if k == 'OpenAction':
                        self.objects[key].isDelayJS = True
                        for type,childkey in self.objects[key].children:
                            if type == 'OpenAction':
                                if childkey in self.objects:
                                    self.objects[childkey].isDelayJS = True
                                else:
                                    print 'erorr: not a valid object for child'

                    if k == 'JS' or k == 'JavaScript':
                        self.objects[key].isJS = True
                        for type,childkey in self.objects[key].children:
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
                        for type, childkey in self.objects[key].children:
                            if type == 'Contents':
                                self.pages.append(childkey)

                    #populate pdfobj's doc_properties with those that exist
                    enum_properties = ['Title','Author','Subject','Keywords','Creator','Producer','CreationDate','ModDate']

                    if k in enum_properties:
                            value = kval
                            value = re.sub('[\xff\xfe\x00]','',value)
                            isReference = re.match('^\d+\s+\d+\s+R$',value)
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
                                value = re.sub('\'','\\x27',value)
                                self.objects[key].staticScript += 'info.%s = String(\'%s\');\n' % (k.lower(),value)
                                self.objects[key].staticScript += 'app.doc.%s = String(\'%s\');\n' % (k.lower(),value)
                    
                #try this before doing anything
                #try:
                #    self.objects[key].tagstream = zlib.decompress(self.objects[key].tagstream)
                #except zlib.error, msg:
                #    pass 

                for k, kval in self.objects[key].tags:
                    if k == 'FlateDecode' or k == 'Fl': 
                        try:
                            self.objects[key].tagstream = zlib.decompress(self.objects[key].tagstream)
                        except zlib.error, msg:
                            if pdf.DEBUG:
                                print 'failed to decompress object %s' % (key)
                            self.objects[key].tagstream = '' #failed to decompress

                    if k == 'ASCIIHexDecode' or k == 'AHx':
                        result = ''
                        counter = 0
                        self.objects[key].tagstream = re.sub('[^a-fA-F0-9]+','',self.objects[key].tagstream)
                        for i in range(0,len(self.objects[key].tagstream),2):
                            result += chr(int('0x'+self.objects[key].tagstream[i:i+2],0))
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

    def is_valid(self):
        if self.indata.startswith('%PDF-') or self.indata.startswith('%%PDF-'):
            return True
        return False
        
    def __repr__(self):
        if not self.is_valid():
            return 'Invalid PDF file "%s"' % (self.infile)
        out = 'PDF file %s has %d obj items\n' % (self.infile,len(self.objects))
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
                value = re.sub('\'','\\x27',value)
                if self.objects[jskey].isAnnot:
                    out += 'var zzza = []; if(zzzannot.length > 0){ zzza=zzzannot.pop(); } zzza.push({subject:\'%s\'}); zzzannot.push(zzza);\n' % (value) #getAnnots
                    if self.objects[jskey].knownName:
                        if self.objects[jskey].subj:
                            subj = self.objects[jskey].subj
                        else:
                            subj = value
                        subj = re.sub('[\x00-\x1f\x7f-\xff]','',subj)
                        out += 'zzzannot2["%s"] = {subject:\'%s\'};\n' % (self.objects[jskey].knownName,subj) #getAnnot
                for property in self.objects[jskey].doc_properties:
                    out += 'info.%s = String(\'%s\');\n' % (property,value)
        for page in self.pages:
            if page in self.objects:
                lines = self.objects[page].tagstream.split('\n')
                out += 'c = []; '
                for line in lines:
                    textBE = re.findall('BT[^(]*\(([^)]+)\)[^)]*?ET',line)
                    for hexdata in textBE:
                        words = hexdata.split(' ')
                        for word in words:
                            out += 'c.push("%s"); ' % (re.sub('([^a-zA-Z0-9])', lambda m: '\\x%02x' % ord(m.group(1)),word))
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
                parsed_data = parsed_header + parsed_data

                if pdf.DEBUG:
                    if len(parsed_data) > 0:
                        print 'parsed JavaScript (xml, in pdf) %d bytes' % (len(parsed_data))
                    else:
                        num_stored = 0
                        for format,store_data in self.objects[jskey].hparser.storage:
                            fout = open('%s.stored_item_%02d' % (self.infile,num_stored), 'wb')
                            try: 
                                decoded_store_data = base64.b64decode(store_data)
                                fout.write(decoded_store_data)
                                print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(decoded_store_data), self.infile,num_stored)
                            except:
                                fout.write(store_data)
                                print 'Wrote %d bytes in EmbeddedFile to %s.stored_item_%02d' % (len(store_data), self.infile,num_stored)

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
                    

            if self.objects[jskey].isJS:
                if pdf.DEBUG:
                    print 'Found JavaScript in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                out += self.objects[jskey].tagstream
            elif self.objects[jskey].isDelayJS:
                if pdf.DEBUG:
                    print 'Found JavaScript (delayed) in %s (%d bytes)' % (jskey, len(self.objects[jskey].tagstream))
                delayout += self.objects[jskey].tagstream

            if pdf.DEBUG:
                if self.objects[jskey].isJS or self.objects[jskey].isDelayJS:
                    print '\tchildren ' + str(self.objects[jskey].children) 
                    print '\ttags ' + str(self.objects[jskey].tags)
                    print '\tindata = ' + re.sub('[\n\x00-\x19\x7f-\xff]','',self.objects[jskey].indata)[:100]

        if len(out+delayout) <= 0:
            #Basically if we don't find ANY JavaScript, then we can parse the other elements
            for jskey in self.objects.keys():
                sloppy = re.search('function |var ', self.objects[jskey].tagstream)
                if sloppy:
                    out += self.objects[jskey].tagstream
                    if pdf.DEBUG:
                        print 'Sloppy PDF parsing found %d bytes of JavaScript' % (len(out))

        return out+delayout, headersjs

    @staticmethod
    def applyFilter(input):
        output = re.sub('^[\x00-\x19\x7f-\xff\n\s]*[\x00-\x19\x7f-\xff]','',input) #look for starting non-ascii characters
        output = re.sub('[\x00-\x19\x7f-\xff][\x00-\x19\x7f-\xff\r\s]*$','',output) #look for trailing non-ascii characters
        return output

def main(files):
    pdf.DEBUG = True
    html.debug = True
    for file in files:
        data = ''
        if os.path.exists(file):
            fin = open(file,'r')
            data = fin.read()
            fin.close()

        mypdf = pdf(data,file)
        if mypdf.is_valid():
            print 'parsing %s' % file
            mypdf.parse()
            decoded,decoded_headers = mypdf.getJavaScript()

            if len(decoded) > 0:
                decoded = decoded_headers + decoded
                fout = open(file+'.out','w')
                if fout:
                    print 'Wrote JavaScript (%d bytes -- %d headers / %d code) to file %s' % (len(decoded), len(decoded_headers), len(decoded) - len(decoded_headers), file+'.out') 
                    fout.write(decoded)
                    fout.close()
            else:
                print 'Didnt decode any JavaScript within PDF file'
        else:
            print('warn: ignoring non-pdf file ' + file)
    

if __name__ == '__main__':
    for i in sys.argv[1:]:
        main(glob.glob(i))
