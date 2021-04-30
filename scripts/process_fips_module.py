#!/usr/bin/env python3
"""
This script facilitaties module integrity verification for FIPS 140 by processing the input ELF
shared object module and replacing key variables so that the module can calculate its own base
address, and thereby HMAC its own memory, at runtime.

Requires PyElfTools: https://github.com/eliben/pyelftools

Copyright (c) Microsoft Corporation. Licensed under the MIT license.
"""

import argparse
import hashlib
import hmac
import io
import logging
import os
import secrets
import stat
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection, Symbol
from elftools.elf.segments import Segment

KEY_NAME = "SymCryptVolatileFipsHmacKey"
KEY_RVA_NAME = "SymCryptVolatileFipsHmacKeyRva"
BOUNDARY_OFFSET_NAME = "SymCryptVolatileFipsBoundaryOffset"
DIGEST_NAME = "SymCryptVolatileFipsHmacDigest"

PLACEHOLDER_VALUE = struct.pack("Q", 0x8BADF00D)
PLACEHOLDER_ARRAY = bytes((
    0x5B, 0x75, 0xBB, 0xE4, 0x9E, 0x18, 0x03, 0x55,
    0x08, 0x4E, 0x3F, 0xE7, 0x60, 0x7E, 0x4F, 0x08,
    0xAA, 0x77, 0x0F, 0x0B, 0xAB, 0xC6, 0x58, 0x5A,
    0xA9, 0x9F, 0x83, 0x4B, 0xD0, 0x6E, 0x67, 0x05))

# Writeable flag for segments since elftools doesn't define it
PF_W = 2

class Variable(object):
    """
    Wrapper for a pyelftools Symbol which makes it easier to get the value and offset/
    virtual address of the object that the symbol represents.
    """

    def __init__(self, elf_file, name):
        """
        Initializes a Variable object by finding the symbol name in the symbol table and mapping
        it to the offset in the file.
        """

        self.elf_file = elf_file
        self.name = name

        symtab = self.elf_file.get_section_by_name(".symtab")
        symbols = symtab.get_symbol_by_name(name)
        assert(len(symbols) == 1)
        self.symbol = symbols[0]

        self.vaddr = self.symbol.entry["st_value"]
        self.length = self.symbol.entry["st_size"]
        self.section = self.elf_file.get_section(self.symbol["st_shndx"])
        self.section_offset = self.vaddr - self.section.header["sh_addr"]
        self.offset = self.section.header["sh_offset"] + self.section_offset

    @property
    def value(self):
        return self.section.data()[self.section_offset:self.section_offset + self.length]

    @value.setter
    def value(self, value):
        assert(type(value) == bytes)
        assert(len(value) == self.length)
        assert(bool(self.section.compressed) is False)

        # The .data() method returns a bytes object. We can't use it to write back to the original
        # buffer, so we need to find the appropriate section within the stream using sh_offset and
        # write to that.
        logging.debug("Writing {} to offset {}".format(value.hex(), hex(self.offset)))
        self.section.stream.seek(self.offset)
        self.section.stream.write(value)

    def set_value(self, format, *args):
        new_value = struct.pack(format, *args)
        assert(len(new_value) == self.length)

        logging.debug("Changing {} value".format(self.name))

        self.value = new_value

def log_variable(var):
    logging.debug("{}: offset {}, virtual address {}, Value {}".format(
        var.name,
        hex(var.offset),
        hex(var.vaddr),
        var.value.hex()))

def hmac_module(loadable_segments, data_section_offset, key, digest, dump_file_path = None):
    """
    Performs HMAC-SHA256 on module contents and writes it back to the module buffer
    """

    module_bytes = bytearray()
    last_segment_offset = -1

    for (index, segment) in enumerate(loadable_segments):

        segment_hashable_length = 0

        # Ensure the loadable segments were given in ascending order by offset
        # (i.e. the same order as in the file)
        assert(last_segment_offset < segment["p_offset"])

        if segment["p_offset"] + segment["p_filesz"] > data_section_offset:
            segment_hashable_length = data_section_offset - segment["p_offset"]
            module_bytes += segment.data()[:segment_hashable_length]
        else:
            module_bytes += segment.data()
            segment_hashable_length = len(segment.data())

        logging.info("Segment {}: {} - {}".format(
            index,
            hex(segment["p_offset"]),
            hex(segment["p_offset"] + segment_hashable_length)))

        last_segment_offset = segment["p_offset"]

    if dump_file_path is not None:
        with open(dump_file_path, "wb") as dump_file:
            dump_file.write(module_bytes)

    logging.debug("Using key: {}".format(key.value.hex()))
    digest_bytes = hmac.digest(key.value, module_bytes, hashlib.sha256)
    logging.debug("Calculated SHA256 digest: {}".format(digest_bytes.hex()))

    digest.set_value(str(len(digest_bytes)) + "s", digest_bytes)
    log_variable(digest)

def process_loadable_segments(elf_file):
    """
    Finds all loadable segments in the module and ensures that the assumptions made by our runtime
    integrity verification code are valid. Returns the list of loadable segments. If an assumption
    is found to be invalid, an exception will be thrown.
    """

    # Find all loadable segments and calculate their sizes and offsets
    loadable_segments = []
    writeable_segment = None
    for segment in elf_file.iter_segments():
        if segment["p_type"] == "PT_LOAD":

            logging.debug("PT_LOAD: Offset {} VAddr {} PAddr {} FileSz {} MemSz {} Align {}".format(
                hex(segment["p_offset"]),
                hex(segment["p_vaddr"]),
                hex(segment["p_paddr"]),
                hex(segment["p_filesz"]),
                hex(segment["p_memsz"]),
                hex(segment["p_align"])
            ))

            loadable_segments.append(segment)

            if writeable_segment is not None:
                # There must be exactly one writeable segment, and it must be the last of the
                # PT_LOAD segments
                logging.error("Found more than one loadable, writeable segment!")
                raise RuntimeError

            if segment["p_flags"] & PF_W != 0:                
                writeable_segment = segment

    writeable_segment_sections = []
    for section in elf_file.iter_sections():
        if writeable_segment.section_in_segment(section):
            writeable_segment_sections.append(section)

    # We set our FIPS module boundary based on where the .data section starts (since it and the
    # .bss section cannot be included in the HMAC). Therefore, .data and .bss must be the second
    # last and last sections of that segment, respectively.
    if writeable_segment_sections[-2].name != ".data" or \
        writeable_segment_sections[-1].name != ".bss":
        logging.error("Unexpected section order in writeable segment!")
        raise RuntimeError

    return loadable_segments

def main():
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Postprocess SymCrypt shared object module")
    parser.add_argument("input", type=str, help = "Path to SymCrypt module")
    parser.add_argument("-d", "--debug", action = "store_true", help = "Enable debug output (also dumps hashable module contents to file)")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG)
    else:
        logging.basicConfig(level = logging.INFO)

    with open(args.input, "rb") as input_file:
        buffer = input_file.read()
        buffer_stream = io.BytesIO(buffer)

    # Copy the original input file to a backup file
    os.replace(args.input, args.input + ".bak")

    elf_file = ELFFile(buffer_stream)
    loadable_segments = process_loadable_segments(elf_file)

    # Find the HMAC key placeholder and replace it with a randomly generated key
    key_variable = Variable(elf_file, KEY_NAME)
    assert(key_variable.value == PLACEHOLDER_ARRAY)

    random_key = secrets.token_bytes(len(key_variable.value)) # NB: not actually a secret
    key_variable.set_value(str(len(random_key)) + "s", random_key)
    log_variable(key_variable)

    # Find the HMAC key relative virtual address placeholder and replace it with
    # the actual relative virtual address of the HMAC key
    key_rva_variable = Variable(elf_file, KEY_RVA_NAME)
    assert(key_rva_variable.value == PLACEHOLDER_VALUE)

    key_rva_variable.set_value("Q", key_variable.vaddr)
    log_variable(key_rva_variable)

    # Find the FIPS module boundary placeholder and replace it with the our actual
    # FIPS module boundary, which we have defined to be the start of the .data section
    fips_boundary_variable = Variable(elf_file, BOUNDARY_OFFSET_NAME)
    assert(fips_boundary_variable.value == PLACEHOLDER_VALUE)

    data_section = elf_file.get_section_by_name(".data")
    data_section_offset = data_section["sh_offset"]

    fips_boundary_variable.set_value("Q", data_section_offset)
    log_variable(fips_boundary_variable)

    # Find the HMAC digest placeholder, HMAC the loadable segments of the module, and replace
    # the placeholder with the actual digest
    digest_variable = Variable(elf_file, DIGEST_NAME)
    assert(digest_variable.value == PLACEHOLDER_ARRAY)

    hmac_module(loadable_segments, data_section_offset, key_variable, digest_variable,
        dump_file_path = args.input + ".loadable.bin" if args.debug else None)

    with open(args.input, "wb") as output_file:
        output_file.write(buffer_stream.getbuffer())

    # chmod 0755 the new output file so that it"s marked as executable (required by some platforms)
    os.chmod(args.input, 
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | # User: read, write, execute
        stat.S_IRGRP | stat.S_IXGRP | # Group: read, execute
        stat.S_IXOTH | stat.S_IXOTH) # Other: read, execute

    logging.info("Success!")

if __name__ == "__main__":
    main()