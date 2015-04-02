#!/usr/bin/python
#Blake Hartstein v0.1c (beta) detection interface
#Goal: use rules files to find content
#June 24, 2009

import sys
import os
import re
import yara

class rules:
    def __init__(self, ruleinput='', respectLevel=True):
        '''ruleinput is a string that is the rule contents/data'''
        #self.file = file
        self.patterns = []
        self.ruleinput = ruleinput

        if len(ruleinput) <= 0:
            if os.path.exists('rules'):
                fin = open('rules', 'r')
                if fin:
                    self.ruleinput = fin.read()
                    fin.close()
        self.loadfile()
        self.respectLevel = respectLevel
        #'detection.py.yara.rules')

    def loadfile(self):
        #previously this accepted filename as input, now we just use the rule input string
        #self.rules = yara.compile(self.file)
        self.rules = yara.compile(source=self.ruleinput)

    def process(self, data, current_level=0, from_pdf=True):
        ret = [] #return value of all detections
        matches = self.rules.match(data=data)
        if matches:
            for match in matches:
                alert = True
                num = 0
                ref = [] #[str(match)]
                rulemsg = str(match)
                msg = []


                hidden = False
                impact = 10

                if 'impact' in match.meta:
                    impact = match.meta['impact']
                
                if 'ref' in match.meta:
                    ref.append(match.meta['ref'])
                if 'hide' in match.meta:
                    hidden = match.meta['hide']

                if hidden:
                    msg.append(' ')
                else:
                    if isinstance(match.strings, list):
                        for s in match.strings:
                            msg.append(s[2])
                    else:
                        for s in match.strings:
                            msg.append(match.strings[s])

                #for tag in match.tags:
                if 'decodedOnly' in match.tags and current_level <= 0:
                    if self.respectLevel:
                        alert = False
                if 'decodedPDF' in match.tags:
                    if not from_pdf:
                        alert = False   
                if 'info' in match.tags:
                    impact = 0
                if 'warn' in match.tags:
                    impact = 5
                
                

                        
                if alert:
                    ret.append([num, ref, msg, impact, rulemsg])
        return ret

    def has_html(self, data):
        #not used
        return re.search('<script|<html|<body', data)

    def has_javascript(self, data):
        data = re.sub('\0', '', data)
        #if data.startswith('%PDF-') or data.startswith('%%PDF-'):
        #    #assume JavaScript to force parsing of PDF file
        #    return 1
        #if data.startswith('CWS') or data.startswith('FWS'):
        #    #assume JavaScript to force parsing of SWF file
        #    return 1

        return re.search('<script|document.write|eval\(|function |function\(|unescape[\(;]|var |=\s*[\'"][^\'"\\\n]+[\'"];', data, re.UNICODE)


if __name__ == '__main__':
    rin = open('testrule', 'r')
    rin_txt = rin.read()
    rin.close()

    r = rules(rin_txt, False) #Don't respect level because we aren't decoding
    for file in sys.argv[1:]:
        fin = open(file, 'rb')
        data = fin.read()

        txt = ''

        maximpact = 0
        res = r.process(data)
        for num, ref, msg, impact, rulemsg in res: #'you lose String.fromCharCode haha eval')
            if impact > maximpact:
                maximpact = impact
            #txt += '   impact %d \t%s %s \t%s\n' % (impact,rulemsg,msg,ref)
            txt += '   impact %d \t%s \t%s\n' % (impact, rulemsg, ref)
        txt += '\n'

        print 'Detection %d file:%s\n%s' % (maximpact, file, txt)

