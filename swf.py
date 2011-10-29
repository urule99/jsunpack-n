#!/usr/bin/python
'''
Blake Hartstein v0.1a (alpha) SWF parser
Goal: extract useful information from SWF/Flash Files
	(especially URLs!)
September 23, 2009

Command line usage: 
$ ./swf.py [swf file]
'''
import os
import re
import sys
import zlib
import glob

tags = 	{
	0:'End',
	1:'ShowFrame',
	2:'DefineShape',
	4:'PlaceObject',
	5:'RemoveObject',
	6:'DefineBits',
	7:'DefineButton',
	8:'JPEGTables',
	9:'SetBackgroundColor',
	10:'DefineFont',
	11:'DefineText',
	12:'DoAction',
	13:'DefineFontInfo',
	14:'DefineSound',
	15:'StartSound',
	17:'DefineButtonSound',
	18:'SoundStreamHead',
	19:'SoundStreamBlock',
	20:'DefineBitsLossless',
	21:'DefineBitsJPEG2',
	22:'DefineShape2',
	23:'DefineButtonCxform',
	24:'Protect',
	26:'PlaceObject2',
	28:'RemoveObject2',
	32:'DefineShape3',
	33:'DefineText2',
	34:'DefineButton2',
	35:'DefineBitsJPEG3',
	36:'DefineBitsLossless2',
	37:'DefineEditText',
	39:'DefineSprite',
	41:'SerialNumber', #not in spec?
	43:'FrameLabel',
	45:'SoundStreamHead2',
	46:'DefineMorphShape',
	48:'DefineFont2',
	56:'ExportAssets',
	57:'ImportAssets',
	58:'EnableDebugger',
	59:'DoInitAction',
	60:'DefineVideoStream',
	61:'VideoFrame',
	62:'DefineFontInfo2',
	64:'EnableDebugger2',
	65:'ScriptLimits',
	66:'SetTabIndex',
	69:'FileAttributes',
	70:'PlaceObject3',
	71:'ImportAssets2',
	73:'DefineFontAlignZones',
	74:'CSMTextSettings',
	75:'DefineFont3',
	76:'SymbolClass',
	77:'Metadata',
	78:'DefineScalingGrid',
	82:'DoABC',
	83:'DefineShape4',
	84:'DefineMorphShape2',
	86:'DefineSceneAndFrameLabelData',
	87:'DefineBinaryData',
	88:'DefineFontName',
	89:'StartSound2',
	90:'DefineBitsJPEG4',
	91:'DefineFont4',
	}
actions = {
	0x04:'ActionNextFrame',
	0x05:'ActionPrevFrame',
	0x06:'ActionPlay',
	0x07:'ActionStop',
	0x08:'ActionToggleQuality',
	0x09:'ActionStopSounds',
	0x0a:'ActionAdd',
	0x0b:'ActionSubtract',
	0x0c:'ActionMultiply',
	0x0d:'ActionDivide',
	0x0e:'ActionEquals',
	0x0f:'ActionLess',
	0x10:'ActionAnd',
	0x11:'ActionOr',
	0x12:'ActionNot',
	0x13:'ActionStringEquals',
	0x14:'ActionStringLength',
	0x15:'ActionStringExtract',
	0x17:'ActionPop',
	0x18:'ActionToInteger',
	0x1c:'ActionGetVariable',
	0x1d:'ActionSetVariable',
	0x20:'ActionSetTarget2',
	0x21:'ActionStringAdd',
	0x22:'ActionGetProperty',
	0x23:'ActionSetProperty',
	0x24:'ActionCloneSprite',
	0x25:'ActionRemoveSprite',
	0x26:'ActionTrace',
	0x27:'ActionStartDrag',
	0x28:'ActionEndDrag',
	0x29:'ActionStringLess',
	0x30:'ActionRandomNumber',
	0x31:'ActionMBStringLength',
	0x32:'ActionCharToAscii',
	0x33:'ActionAsciiToChar',
	0x34:'ActionGetTime',
	0x35:'ActionMBStringExtract',
	0x36:'ActionMBCharToAscii',
	0x37:'ActionMBAsciiToChar',
	0x3a:'ActionDelete',
	0x3b:'ActionDelete2',
	0x3c:'ActionDefineLocal',
	0x3d:'ActionCallFunction',
	0x3f:'ActionModulo',
	0x3e:'ActionReturn',
	0x40:'ActionNewObject',
	0x41:'ActionDefineLocal2',
	0x42:'ActionInitArray',
	0x43:'ActionInitObject',
	0x44:'ActionTypeOf',
	0x45:'ActionTargetPath',
	0x46:'ActionEnumerate',
	0x47:'ActionAdd2',
	0x48:'ActionLess2',
	0x49:'ActionEquals2',
	0x4a:'ActionToNumber',
	0x4b:'ActionToString',
	0x4c:'ActionPushDuplicate',
	0x4d:'ActionStackSwap',
	0x4e:'ActionGetMember',
	0x4f:'ActionSetMember',
	0x50:'ActionIncrement',
	0x51:'ActionDecrement',
	0x52:'ActionCallMethod',
	0x53:'ActionNewMethod',
	0x60:'ActionBitAnd',
	0x61:'ActionBitOr',
	0x62:'ActionBitXor',
	0x63:'ActionBitLShift',
	0x64:'ActionBitRShift',
	0x65:'ActionBitURShift',
	0x81:'ActionGotoFrame',
	0x83:'ActionGetURL',
	0x87:'ActionStoreRegister',
	0x88:'ActionConstantPool',
	0x8a:'ActionWaitForFrame',
	0x8b:'ActionSetTarget',
	0x8c:'ActionGoToLabel',
	0x8d:'ActionWaitForFrame2',
	0x94:'ActionWith',
	0x96:'ActionPush',
	0x9a:'ActionGetURL2',
	0x9b:'ActionDefineFunction',
	0x9f:'ActionGotoFrame2',
	0x99:'ActionJump',
	0x9d:'ActionIf',
	0x9e:'ActionCall',
	}
datatype = {
	0:'string',
	1:'floating-point literal',
	2:'null',
	3:'undefined',
	4:'register',
	5:'Boolean',
	6:'double',
	7:'integer',
	8:'constant8',
	9:'constant16',
	}


def reverseInt(input, debug=False):
	#input is a string!
	if len(input) == 1:
		return ord(input)
	elif len(input) == 0:
		return 0

	output = 0
	shift = 0
	for arr in range(0, len(input)):
		i = input[arr]
		output += (ord(i) << shift)
		
		if debug:
			print '\tat index arr=%d, shift by %d for ord(i)=%d [%d]' % (arr, shift, ord(i), (ord(i) << shift))
		shift += 8
	if debug:
		print '\t\treturned %d' % (output)
	return output
def get_string(data):
	#return string at the current position
	for i in range(0, len(data)):
		if ord(data[i]) == 0:
			return data[0:i]
	return ''
	

def process_action(name, data):
	txt, url = '', ''
	if name == 'ActionPush':
		type = ord(data[0])
		txt += '\tdatatype[%d]=' % (type)
		if type in datatype:
			txt += datatype[type]

			if datatype[type] == 'string':
				s = get_string(data[1:])
				txt += '(%s)' % (s)
				if s.startswith('http'):
					url = s
				
	elif name == 'ActionGetURL':
		url = get_string(data)
		target = get_string(data[len(url) + 1:])	

		url = re.sub('[^\x20-\x7e]', '', url)
		target = re.sub('[^\x20-\x7e]', '', target)

		txt += ' %s' % (url)
		if target:
			txt += ' (%s)' % (target)
	elif name == 'ActionGetProperty':
		pass #built-in vars
						
	else:
		return txt, url
	return txt, url

def process_tag(name, data):
	txt = ''
	urls = []

	if name == 'DoAction':
		while len(data) > 0:
			actionCode = ord(data[0])
			txt += '\tactionCode %s ' % (hex(actionCode))
			actionlen = 0
			if actionCode >= 0x80:
				#2 bytes
				if len(data) >= 3:
					actionlen = reverseInt(data[1:3])
				offset = 3
			else:
				#1 bytes
				if len(data) >= 2:
					actionlen = reverseInt(data[1], True)
				offset = 2
			txt += 'len(%d) ' % (actionlen)

			if actionCode in actions:
				txt += '\t%s' % (actions[actionCode])
				if (offset + actionlen) <= len(data):
					t, u = process_action(actions[actionCode], data[offset:offset + actionlen])
					txt += t
					urls.append(u)
				#else:
				#	txt += 'unable to process because length exceeds data\n'
			else:
				txt += '\tunknownAction'

			txt += '\n'
			if (offset + actionlen) < len(data):
				data = data[offset + actionlen:]
			else:
				data = ''
	else:
		return '', urls

	return txt, urls


def swfstream(data):
	out = ''
	urls = []

	try:
		if data.startswith('CWS'):
			#compressed
			header = data[3:8]

			try:
				data = zlib.decompress(data[8:])
				#print 'decompressed %d bytes' % len(data)
				data = 'FWS' + header + data
			except zlib.error, msg:
				return 'failed to decompress', urls

		if data.startswith('FWS'):
			#flash file
			offset = 8

			header = data[3:8]
			version = ord(header[0])
			entirelen = reverseInt(header[1:5]) #ord(header[1]) #incorrect, its 4 bytes long / reversed

			#process rect structure
			rectbits = (ord(data[offset]) >> 3)

			if ((rectbits * 4) % 8) == 0:
				more = rectbits * 4 / 8
			else:
				more = rectbits * 4 / 8 + 1

			#print 'since x4 = %d, we need %d more bytes' % (rectbits*4,more)
			
			offset += more + 1 #one more for the rectbits [size]

			offset += 4 #Framerate, Framecount
			out += 'processing flash file [version %d] (length %d, actual length %d)' % (version, entirelen, len(data))

			hidden = {}
			urls = []
			while offset + 1 < len(data):
				#CWS/j.winxyz.com_win_j_dadongf.swf
				b, a = data[offset], data[offset + 1]
				#print '\tusing ', hex(ord(a)), hex(ord(b))
				offset += 2

				tagtype = ((ord(a) << 2) + (ord(b) >> 6)) & 0x03ff
				shortlen = (ord(b) & 0x3f)

			
				if shortlen == 0x3f:
					#txt += 'long (%d)' % (shortlen)
					shortlen = reverseInt(data[offset:offset + 4]) 
					offset += 4
				if tagtype in tags:
					if shortlen > 0:
						out += 'type=%s\tlength=%s\tname=%s\n' % (hex(tagtype), shortlen, tags[tagtype])
						t, us = process_tag(tags[tagtype], data[offset:offset + shortlen])
						out += t
						for u in us:
							stopAt = u.find(' ')
							if stopAt == -1:
								stopAt = u.find('\r')

							if stopAt > 0: #leading space is ok
								u = u[:stopAt]

							if not u.startswith('FSCommand:'): #don't want flash commands
								if u and (not u in urls):
									urls.append(u)
					else:
						if tags[tagtype] in hidden:
							hidden[tags[tagtype]] += 1
						else:
							hidden[tags[tagtype]] = 1

					#if shortlen > 0:
					#	txt += '\tdata[%d to %d]=' % (offset, offset+shortlen)
					#	for i in range(offset,offset+shortlen):
					#		txt += hex(ord(data[offset]))
				else:
					out += 'type=%s (%d)\tlength=%s\tname=%s\n' % (hex(tagtype), tagtype, shortlen, 'unknown')
				offset += shortlen
			out += '\ntags (with counts) of length=0\n'
			
			firstTime = True
			for i in hidden:
				if not firstTime:
					out += ', '
				out += '%s:%d' % (i, hidden[i])
				firstTime = False

			return out, urls
		else:
			return 'Invalid SWF file', urls
	except:
		return 'Invalid SWF format', urls

def main(files):
	for file in files:
		if os.path.exists(file):
			fin = open(file, 'r')
			data = fin.read()
			fin.close()

			if data.startswith('CWS') or data.startswith('FWS'):
				msgs, urls = swfstream(data)
			
				print msgs
				if len(urls) > 0:
					print file, urls
				
			else:
				print('warn: ignoring non-SWF file ' + file)


if __name__ == '__main__':
	for i in sys.argv[1:]:
		main(glob.glob(i))
