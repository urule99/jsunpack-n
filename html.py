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
import re
import sys
try:
    from bs4 import BeautifulSoup
except ImportError:
    # BeautifulSoup 4.x not installed trying BeautifulSoup 3.x 
    try:
        from BeautifulSoup import BeautifulSoup
    except ImportError:
        print ('BeautifulSoup not installed')
        exit(-1)

class Parser:
    '''
    A simple HTML language parser. Uses the 'htmlparse.conf' file to define rules.
    Please read that file for more information on the syntax
    
    <Parser obj>.storage is a 'special' return field. You should only use it if you 
    wish to get the result in python instead of via an output string.
    '''
    debug = False
    def __init__(self, htmlparseconfig):
        self.storage = []
        self.html_definitions = {}
        self.html_filters = {}
        self.html_parse_rules = []
        
        try:
            htmlrules = htmlparseconfig.splitlines()
        except:
            htmlrules = []
            print 'Problem while parsing HTML parsing rules'

        line = 0
        for htmlrule in htmlrules:
            line += 1
            htmlrule = re.sub('\n', '', htmlrule)
            if not re.match('^\s*$|^#', htmlrule):
                htmlrule = re.sub('[ \t]+', ' ', htmlrule)
                field = htmlrule.split(' ')

                if htmlrule.startswith('!define'):
                    if len(field) > 1:
                        name, value = field[1], ' '.join(field[2:])
                        self.html_definitions[name] = value

                elif htmlrule.startswith('!parse'):
                    if len(field) == 4:
                        tag = field[1]
                        if tag == '*':
                            tag = True
                        attrib = {}
                        invals = field[2].split(',')
                        for val in invals:
                            if val == '*' or val.startswith('!'):
                                pass
                            else:
                                attrib[val] = True
                        hformat, outvals = field[3].split(':')
                        outvals = outvals.split(',')
                        self.html_parse_rules.append([tag, attrib, invals,
                                                      hformat, outvals])

                elif htmlrule.startswith('!filter'):
                    if len(field) > 2:
                        tag, value = field[1], ' '.join(field[2:])
                        self.html_filters[tag] = re.sub('^\s+|\s+$', '', value)
                else:
                    print 'fatal: invalid htmlparse.config line: %d' % line

        if self.debug:
            print ('done loading htmlparse, (%d parse_rules, %d definitions, '
                   '%d filters)' % (len(self.html_parse_rules), 
                                    len(self.html_definitions), 
                                    len(self.html_filters)))


    def htmlparse(self, data):
        '''
        Input: can be html code or raw JavaScript code
        Output: an array of [headers, raw JavaScript]
        '''
        outheader, out = '', ''
        data = re.sub('\x00', '', data)

        try:
            soup = BeautifulSoup(data)
        except:
            print('Fatal error during HTML parsing')
            return '', '' 
        
        for tag, attrib, invals, hformat, outvals in self.html_parse_rules:
            for htm in soup.findAll(tag, attrib):
                now = {}
                ignore = False #if a negated match occurs
                for val in invals:
                    if val.startswith('!'):
                        #negated match
                        val = val[1:]
                        try:
                            now[val] = str(htm[val])
                            ignore = True
                        except:
                            pass #expected behavior

                if not ignore:
                    for val in outvals:
                        if val == '*':
                            now['*'] = ''
                        elif val == 'contents':
                            try: 
                                now['contents'] = ' '.join(map(str, 
                                                               htm.contents))
                            except KeyError: 
                                now['contents'] = ''
                            except UnicodeEncodeError: 
                                now['contents'] = ' '.join(map(str, 
                                                               str(htm.contents)
                                                               ))
                        elif val == 'name':
                            try: 
                                now['name'] = htm.name
                            except KeyError: 
                                now['name'] = ''
                        else:
                            try: 
                                now[val] = str(htm[val])
                            except KeyError: 
                                now[val] = ''

                    #normalize when assigning to variables
                    for k in now: 
                        # if this fails, it means that we are trying to get the
                        # result in python
                        if hformat in self.html_definitions:
                            if not hformat.startswith('raw'):
                                now[k] = re.sub('([^a-zA-Z0-9])', 
                                                lambda m: ('\\x%02x' 
                                                           % ord(m.group(1))), 
                                                now[k])
                                now[k] = "'%s'" % now[k]

                    # if this fails, it means that we are trying to get the 
                    # result in python
                    if hformat in self.html_definitions: 
                        myfmt = re.sub('^\s+', '', 
                                       self.html_definitions[hformat]
                                       ).split('%s')
                        if len(myfmt) - 1 == len(outvals):
                            lineout = ''
                            for i in range(0, len(outvals)):
                                lineout += myfmt[i]
                                lineout += now[outvals[i]]
                            lineout += myfmt[-1] + '\n'

                            if htm.name in self.html_filters:
                                lineout = re.sub(self.html_filters[htm.name], 
                                                 '', lineout)
                            if '*' in self.html_filters:
                                lineout = re.sub(self.html_filters['*'], '', 
                                                 lineout, re.I)
                            if hformat.startswith('header'):
                                outheader += lineout
                            else:
                                out += lineout
                        else:
                            print ('fatal: invalid htmlparse.config hformat, '
                                   'parameter count or definition problem')
                    else:
                        for i in range(0, len(outvals)):
                            self.storage.append([hformat, now[outvals[i]]])
        return str(outheader), str(out)


def main():
    '''
    Testing html Parser with pdf as input
    '''
    Parser.debug = True

    #fin = open('htmlparse.config', 'r')
    #htmlparseconfig = fin.read()
    #fin.close()

    pdfparseconfig = '''
!define rawSCRIPT   ;%s
!parse  script      *   rawSCRIPT:contents
!parse  imagefield1 *   to_python:contents
!filter script      <[/]?script[^>]*>|<!--|//-->
!filter *           ^javascript:\s*|^return\s+
'''
    #xfa:contenttype
    hparser = Parser(pdfparseconfig)
    #hparser = Parser(htmlparseconfig)

    for infile in sys.argv[1:]:
        fin = open(infile, 'rb')
        data = fin.read()
        fin.close()

        parsed_header, parsed = hparser.htmlparse(data)
        parsed = parsed_header + parsed

        if len(parsed) > 0:
            fout = open('%s.out' % infile, 'wb')
            fout.write(parsed)
            fout.close()
            print 'Wrote %s.out (%d bytes)' % (infile, len(parsed))
        else:
            print 'Nothing parsed for %s' % infile

if __name__ == '__main__':
    main()
