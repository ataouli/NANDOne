#!/usr/bin/python

APP_NAME = 'NANDOne'
BUILD_VER = 'v0.02'

import sys
import getopt
import struct
import mmap
import os

NAND_SIZE = 0x13C000000
NAND_SPLIT = NAND_SIZE / 0x20
LOG_BLOCK_SZ = 0x1000

MAGIC_SIZE = 0x4

SFBX_MAGIC = 'SFBX'
GFCX_MAGIC = 'GFCX'
GFCU_MAGIC = 'GFCU'
XVD_MAGIC = 'msft-xvd'

XVD_MAGIC_START = 0x200

SFBX_START = [0x810000,0x10000]
SFBX_MAGIC_START = 0x0

SFBX_ENTS_START = 0x10

SFBX_BLOB_START = 0x3C0
SFBX_BLOB_SIZE = 0x40

SFBX_EN_SIZE = 0x10
SFBX_EN_LBA_START = 0x0 
SFBX_EN_SZ_START = 0x4 

SFBX_ENTS_MAXCNT_FIX = 0x3B

GFCU_MAGIC_START = 0x28
GFCU_ENTS_START = 0xF0

GFCU_BLOB_START = 0xAD8
GFCU_BLOB_SIZE = 0x64

GFCU_EN_SIZE = 0x4C
GFCU_EN_FN_START = 0x0
GFCU_EN_FN_LENGTH = 0x40
GFCU_EN_SIZE_START = 0x40
GFCU_EN_BLOCK_START = 0x44
GFCU_EN_UNKNOWN_START = 0x48
GFCU_EN_EOF_START = 0x4
GFCU_EN_EOF_MAGIC = 0x3FF

GFCU_ENTS_MAXCNT = 0x100

gfcu_arr = []
sfbx_arr = []

KRNL_VER_START = 0x30
KRNL_VER_LENGTH = 0x70

def ReverseByteOrder(data):
	dstr = hex(data)[2:].replace('L','')
	byteCount = len(dstr[::2])
	val = 0
	for i, n in enumerate(range(byteCount)):
		d = data & 0xFF
		val |= (d << (8 * (byteCount - i - 1)))
		data >>= 8
	return val

def ReadUInt16_LE(data,addr):
	return struct.unpack('<H', data[addr:addr+2])[0]

def ReadUInt16_BE(data,addr):
	return struct.unpack('>H', data[addr:addr+2])[0]

def ReadUInt32_LE(data,addr):
	return struct.unpack('<I', data[addr:addr+4])[0]

def ReadUInt32_BE(data,addr):
	return struct.unpack('>I', data[addr:addr+4])[0]

def ReadString(data,addr,size):
	return data[addr:addr+size]

def GetFilesize(fn):
	st = os.stat(fn)
	return st.st_size

def FileExists(fn):
	return os.path.isfile(fn)

def CheckMagic(indata, pos, magic):
	read = ReadUInt32_LE(indata, pos)
	comp = ReadUInt32_LE(magic, 0)
	if read != comp:
		return -1
	return 0

def ReadFile(fn, start, length):
	file = open(fn, 'r+b')
	file.seek(start)
	data = file.read(length)
	file.close()
	return data

def ScanForSFBX(fn):
	file = open(fn, 'r+b')
	sfbx_addr = 0
	for i in xrange(NAND_SIZE/NAND_SPLIT):
		mm = mmap.mmap(file.fileno(),length=NAND_SPLIT, offset=i*NAND_SPLIT)
		for j in xrange(0,(NAND_SPLIT-LOG_BLOCK_SZ), LOG_BLOCK_SZ):
			sfbx_magic = ReadString(mm, j,len(SFBX_MAGIC))
			if(CheckMagic(sfbx_magic, SFBX_MAGIC_START, SFBX_MAGIC) == 0):
				sfbx_addr = j + (i * NAND_SPLIT)
				break
		mm.close()
	file.close()
	return sfbx_addr
	
def GetSizeSFBX(fn, addr):
	if(addr == 0):
		return 0
	for i in xrange(SFBX_ENTS_MAXCNT_FIX):
		total_pos = addr + i * SFBX_EN_SIZE
		entry = ReadFile(fn, total_pos, SFBX_EN_SIZE)

		lba = ReadUInt32_LE(entry, SFBX_EN_LBA_START)
		sz = ReadUInt32_LE(entry, SFBX_EN_SZ_START)
		if ((lba*LOG_BLOCK_SZ) == addr):
			return (sz * LOG_BLOCK_SZ) / 0x10 # Needs division by 0x10
	return 0
	
def DumpSFBX(fn):
	for i in xrange(len(SFBX_START)):
		sfbx_magic = ReadFile(fn, SFBX_START[i], len(SFBX_MAGIC))
		if(CheckMagic(sfbx_magic, SFBX_MAGIC_START, SFBX_MAGIC) == 0):
			sfbxaddr = SFBX_START[i]
			break
		if (i == len(SFBX_START)-1):
			print('SFBX data wasn\'t found. Scanning for it!')
			sfbxaddr = ScanForSFBX(fn)
			break
		
	sfbxsize = GetSizeSFBX(fn,sfbxaddr)
	sfbxaddr = sfbxaddr + SFBX_ENTS_START # Don't want the header
	
	if(sfbxsize == 0):
		print('Size of SFBX wasn\'t found in Adresstable')
		return 0
		
	sfbx_ents_size = sfbxsize - SFBX_BLOB_SIZE - SFBX_ENTS_START
	sfbx_ents_maxcnt = sfbx_ents_size / SFBX_EN_SIZE
		
	#Read adresses in array		
	for j in xrange(sfbx_ents_maxcnt):
		total_pos = sfbxaddr + j * SFBX_EN_SIZE
		entry = ReadFile(fn, total_pos, SFBX_EN_SIZE)

		lba = ReadUInt32_LE(entry, SFBX_EN_LBA_START)
		sz = ReadUInt32_LE(entry, SFBX_EN_SZ_START)
			
		fileaddr = lba * LOG_BLOCK_SZ
			
		# msft-xvd magic doesnt start at 0x0!
		xvd = ReadFile(fn, fileaddr+XVD_MAGIC_START, len(XVD_MAGIC))
		if(xvd == XVD_MAGIC):
			magic = 'XVD'
		else:
			magic = ReadFile(fn, fileaddr, MAGIC_SIZE)
			
		sfbx_arr.append([])
		sfbx_arr[-1].append(total_pos)
		sfbx_arr[-1].append(lba)
		sfbx_arr[-1].append(sz)
		sfbx_arr[-1].append(magic)
	return j-1

def ExtractSFBXData(fn):
	infile = open(fn, 'r+b')
	count = 0
	for i in xrange(len(sfbx_arr)):
		if (sfbx_arr[i][2] != 0): # Only extract if entry holds a size
			count = count + 1
			addr = sfbx_arr[i][1] * LOG_BLOCK_SZ
			size = sfbx_arr[i][2] * LOG_BLOCK_SZ
			magic = sfbx_arr[i][3]
			
			if (magic.isalpha()):
				fn_out = '{:#02}.{}'.format(count,magic)
			else:
				fn_out = '{:#02}.bin'.format(count)
			outfile = open(fn_out, 'w+b')
			print('Extracting @ {:#08x}, size: {}kb to \'{}\''.\
					format(addr,size/1024,fn_out))
					
			mm = mmap.mmap(infile.fileno(), length=size, offset=addr)
			outfile.write(mm)	
			outfile.close()
			mm.close()
	infile.close()

def PrintSFBX():
	print('\nSFBX Entries')
	print('-----------\n')
	for i in xrange(len(sfbx_arr)):
		if (sfbx_arr[i][2] == 0):
			continue                                               
		print('Entry 0x{0:02X} : found @ pos: {1:08X}'.\
				format(i, sfbx_arr[i][0]))
		print('\tLBA: {0:08X} (addr {1:09X})'.\
				format(sfbx_arr[i][1], (sfbx_arr[i][1] * LOG_BLOCK_SZ)))
		print('\tSize: {0:08X} ({0} Bytes, {1}kB, {2}MB)'.\
				format((sfbx_arr[i][2] * LOG_BLOCK_SZ),\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)/1024,\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)/1024/1024))
		if (sfbx_arr[i][3].isalpha()):
			print('*** MAGIC: {0} ***'.\
				format(sfbx_arr[i][3]))

# Returns: total addr, total_size 		
def GetEntryByMagic(magic):
	for i in xrange(len(sfbx_arr)):
		if (sfbx_arr[i][3] == magic):
			return (sfbx_arr[i][1] * LOG_BLOCK_SZ),\
					(sfbx_arr[i][2] * LOG_BLOCK_SZ)
	return 0

# Returns: total_size
def GetEntryByAddr(addr):
	for i in xrange(len(sfbx_arr)):
		if ((sfbx_arr[i][1] * LOG_BLOCK_SZ) == addr):
			return (sfbx_arr[i][2] * LOG_BLOCK_SZ)
	return 0

def DumpKernelVer(data):
	return ReadString(data,KRNL_VER_START, KRNL_VER_LENGTH)

def DumpGFCU(data,startaddr):
	for i in xrange(GFCU_ENTS_MAXCNT):
		pos = startaddr + i*GFCU_EN_SIZE
		entry = data[pos:pos+GFCU_EN_SIZE]

		eof = ReadUInt32_LE(entry, GFCU_EN_EOF_START)
		if (eof == GFCU_EN_EOF_MAGIC):
			return i-1

		fn = ReadString(entry, GFCU_EN_FN_START, GFCU_EN_FN_LENGTH)
		sz = ReadUInt32_LE(entry, GFCU_EN_SIZE_START)
		blk = ReadUInt32_LE(entry, GFCU_EN_BLOCK_START)
		un = ReadUInt32_LE(entry, GFCU_EN_UNKNOWN_START)

		gfcu_arr.append([])
		gfcu_arr[-1].append(pos)
		gfcu_arr[-1].append(fn)
		gfcu_arr[-1].append(sz)
		gfcu_arr[-1].append(blk)
		gfcu_arr[-1].append(un)
				
def PrintGFCU():
	print('\nGFCU Entries')
	print('-----------\n')
	for i in xrange(len(gfcu_arr)):	                                               
		print('Entry 0x{0:02X} : found @ pos: {1:08X}'.\
				format(i, gfcu_arr[i][0]))
		print('\tfilename: {0} (size: {1:09X})'.\
				format(gfcu_arr[i][1], (gfcu_arr[i][2] * LOG_BLOCK_SZ)))
		print('\tBlock: {0:08X} Unknown: {0:08X}'.\
				format((gfcu_arr[i][3] * LOG_BLOCK_SZ),\
					(gfcu_arr[i][4] * LOG_BLOCK_SZ)))

action_arr =	['info', 'Prints the parsed entries'],\
				['extract','Extracts nand content']

def PrintUsage():
	print('Usage:')
	print('\t{0} [action] [dump]'.format(sys.argv[0]))
	print('\nAvailable Action:')
	for i in xrange(len(action_arr)):
		print ('\t{0}\t\t{1}'.format(action_arr[i][0], action_arr[i][1]))
	print('\nExample:')
	print('\t{0} {1} nanddump.bin'.format(sys.argv[0], action_arr[0][0]))

if __name__ == '__main__':
	print('{} {} started\n'.format(APP_NAME, BUILD_VER))
	if len(sys.argv) != 3:
		PrintUsage()
		sys.exit(-1)
	for i in xrange(len(action_arr)):
		if (sys.argv[1] == action_arr[i][0]):
			break
		elif (i == len(action_arr)-1):
			print('ERROR: [action] parameter is invalid!\n')
			PrintUsage()
			sys.exit(-2)
	if (FileExists(sys.argv[2]) == 0):
		print('ERROR: file \'{}\' doesn\'t exist\n'.format(sys.argv[2]))
		PrintUsage()
		sys.exit(-3)
		
############
### MAIN ###
############

action = sys.argv[1]
filename = sys.argv[2]

print('Opening \'{}\''.format(filename))

if (GetFilesize(filename) != NAND_SIZE):
	print('Invalid filesize. Aborting!')
	sys.exit(-4)

print('\nParsing SFBX Entries... ')
sfbx_len = DumpSFBX(filename)
if (sfbx_len == 0):
	print('SFBX not found! Aborting!\n')
	sys.exit(-4)
print('Found {} Entries\n'.format(sfbx_len))


gfcx_addr, gfcx_size = GetEntryByMagic(GFCX_MAGIC)
if (gfcx_addr == 0):
	print ('GFCX MAGIC not found. Exiting!')
	sys.exit(-4)
	
gfcu_addr = gfcx_addr + gfcx_size
gfcu_size = GetEntryByAddr(gfcu_addr)

if (gfcu_size == 0):
	print ('GFCU Entry not found. Exiting!')
	sys.exit(-4)

gfcu = ReadFile(filename, gfcu_addr, gfcu_size)
if CheckMagic(gfcu, GFCU_MAGIC_START, GFCU_MAGIC) == -1:
	print ('GFCU MAGIC not found. Exiting!')
	sys.exit(-4)

print('Parsing GFCU Entries... ')
gfcu_len = DumpGFCU(gfcu,GFCU_ENTS_START)
print('Found {} Entries\n'.format(gfcu_len))

print('Xbox ONE Kernel-Version: {}'.format(DumpKernelVer(gfcu)))
	

if (action == action_arr[0][0]): # 'info'
	PrintSFBX()
	PrintGFCU()
elif (action == action_arr[1][0]): # 'extract'
	ExtractSFBXData(filename)
