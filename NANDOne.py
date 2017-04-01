#!/usr/bin/env python

'''
NANDOne - Xbox One (Codename: Durango) NAND dump parser / extractor
* Maybe one day: " + decryptor"

Credits:
    noob25x / emoose: XVDTool (https://github.com/emoose/xvdtool)
    various people: supplying nand dumps
'''

import io
import os
import sys
import hashlib
import uuid
import binascii
import argparse

from construct import Int8ul, Int16ul, Int16ub
from construct import Int32ul, Int32ub, Int64ul, Int64ub
from construct import Bytes, Array, Padding, Struct

APP_NAME = 'NANDOne'
BUILD_VER = 'v0.03'

FLASH_SIZE_LOG = 0x13BC00000
FLASH_SIZE_RAW = 0x13C000000
LOG_BLOCK_SZ = 0x1000

HEADER_SIZE = 1024
HEADER_MAGIC = b'XBFS'
HEADER_MAGIC = Int32ub.parse(HEADER_MAGIC)

HEADER_HASH_SIZE = 32

HEADER_OFFSETS = [0x10000,
                0x810000,
                0x820000]

FLASH_FILES_COUNT = 25

XVD_MAGIC = 'msft-xvd'
XVD_MAGIC_START = 0x200


FlashFiles = [
    "1smcbl_a.bin",     # 01 1st SMC bootloader, slot A
    "header.bin",       # 02 Flash header
    "devkit.ini",       # 03 devkit init
    "mtedata.cfg",      # 04 MTE data ???
    "certkeys.bin",     # 05 Certificate keys
    "smcerr.log",       # 06 SMC error log
    "system.xvd",       # 07 SystemOS xvd
    "$sosrst.xvd",      # 08 SystemOS reset ???
    "download.xvd",     # 09 Download xvd ???
    "smc_s.cfg",        # 10 SMC config - signed
    "sp_s.cfg",         # 11 SP config - signed
    "os_s.cfg",         # 12 OS config - signed
    "smc_d.cfg",        # 13 SMC config - decrypted
    "sp_d.cfg",         # 14 SP config - decrypted
    "os_d.cfg",         # 15 OS config - decrypted
    "smcfw.bin",        # 16 SMC firmware
    "boot.bin",         # 17 Main Bootloader ???
    "host.xvd",         # 18 HostOS xvd
    "settings.xvd",     # 19 Settings xvd
    "1smcbl_b.bin",     # 20 1st SMC bootloader, slot B
    "bootanim.dat",     # 21 Bootanimation
    "sostmpl.xvd",      # 22 SystemOS template xvd
    "update.cfg",       # 23 Update config / log?
    "sosinit.xvd",      # 24 SystemOS init xvd
    "hwinit.cfg"        # 25 Hardware init config
]


# offset and size need to be multiplied by LOG_BLOCK_SZ
FlashFileEntry = Struct(
    "offset" / Int32ul,
    "size" / Int32ul,
    "unknown" / Int64ul
)

FlashHeader = Struct(
    # HEADER_MAGIC
    "magic" / Int32ul,
    "format_version" / Int8ul,
    "sequence_version" / Int8ul,
    "layout_version" / Int16ul,
    "unknown_1" / Int64ul,
    "unknown_2" / Int64ul,
    "unknown_3" / Int64ul,
    "files" / Array(FLASH_FILES_COUNT, FlashFileEntry),
    Padding(544),
    # GUID
    "guid" / Bytes(16),
    # SHA256 checksum
    "hash" / Bytes(HEADER_HASH_SIZE)
)

class DurangoNand(object):
    extract_info_str = " ... extracting ..."
    def __init__(self, filename):
        self._filename = filename

    @property
    def filename(self):
        return self._filename
    
    @property
    def filesize(self):
        st = os.stat(self.filename)
        return st.st_size

    @property
    def file_exists(self):
        return os.path.isfile(self.filename)

    def _hash(self, data):
        return hashlib.sha256(data).digest()

    def extract_file(self, flash_fd, offset, size, dirname, filename):
        # Read file from nanddump
        flash_fd.seek(offset)
        buf = flash_fd.read(size)
        # Write file to destination path
        try:
            os.mkdir(dirname)
        except FileExistsError as e:
            pass

        dest_path = os.path.join(dirname, filename)
        with open(dest_path, "wb") as dest_fd:
            dest_fd.write(buf)
            dest_fd.flush()

    def parse_fileheader(self, header, flash_fd, do_extract=False):
        guid = uuid.UUID(bytes=header.guid)
        hash = binascii.hexlify(header.hash).decode('utf-8')

        print("Format Version: %i" % header.format_version)
        print("Sequence Version: %i" % header.sequence_version)
        print("Layout Version: %i" % header.layout_version)
        print("GUID: %s" % guid)
        print("Hash: %s" % hash)

        print("- Files:")
        for idx, name in enumerate(FlashFiles):
            offset = header.files[idx].offset * LOG_BLOCK_SZ
            size = header.files[idx].size * LOG_BLOCK_SZ
            if not size:
                print("Not found - file: %s" % name)
                continue
            print("off: 0x%08x, sz: 0x%08x, file: %s %s" % (
                  offset, size, name,
                  self.extract_info_str if do_extract else ""))

            if do_extract:
                self.extract_file(flash_fd, offset, size, 
                                  self.filename + "_" + str(guid), name)

    def parse(self, do_extract):
        if len(FlashFiles) != FLASH_FILES_COUNT:
            print("ERROR: FlashFiles count is incorrect!")
            print("Got %i instead of expected %i entries" % (len(FlashFiles), FLASH_FILES_COUNT))
            return

        if not self.file_exists:
            print("ERROR: file %s does not exist!" % nand.filename)
            return

        if self.filesize == FLASH_SIZE_LOG:
            print("Nanddump type: Logical")
        elif self.filesize == FLASH_SIZE_RAW:
            print("Nanddump type: Raw")
        else:
            print("ERROR: file does not match expected filesize!")
            print("Got 0x%x instead of expected 0x%x bytes" % (self.filesize, FLASH_SIZE))
            return

        print("Nanddump file: %s" % self.filename)
        f = io.open(self.filename, "rb")
        # Search for fixed-offset filesystem header
        for offset in HEADER_OFFSETS:
            f.seek(offset)
            data = f.read(HEADER_SIZE)
            header = FlashHeader.parse(data)
            if header.magic != HEADER_MAGIC:
                continue
            print("-- Filesystem Header @ 0x%x" % offset)
            hash = self._hash(data[:-HEADER_HASH_SIZE])
            if hash != header.hash:
                # Just warn but try to parse anyways
                print("WARNING: Hash of header does not match")
            output = self.parse_fileheader(header, f, do_extract)
        f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse raw Durango Nanddump')
    parser.add_argument('filename', type=str, help='input filename')
    parser.add_argument('--extract', action='store_true', help='extract files from nand')
    print("%s %s started" % (APP_NAME, BUILD_VER))

    args = parser.parse_args()
    nand = DurangoNand(args.filename)
    nand.parse(args.extract)
