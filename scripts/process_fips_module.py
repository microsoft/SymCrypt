#!/usr/bin/env python3
"""
This script facilitaties module integrity verification for FIPS 140 by processing the input ELF
shared object module and replacing key values so that the module can calculate its own base
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

from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_x64, ENUM_RELOC_TYPE_AARCH64

# Names of global constants in the FIPS module that need to be replaced
KEY_NAME = "SymCryptVolatileFipsHmacKey"
KEY_RVA_NAME = "SymCryptVolatileFipsHmacKeyRva"
BOUNDARY_OFFSET_NAME = "SymCryptVolatileFipsBoundaryOffset"
DIGEST_NAME = "SymCryptVolatileFipsHmacDigest"

# Friendly names for Python struct functionality
CHAR_FORMAT_SPECIFIER = "s"
QWORD_FORMAT_SPECIFIER = "Q"
QWORD_BYTE_SIZE = struct.calcsize(QWORD_FORMAT_SPECIFIER)

# Must match the placeholder values in integrity.c
PLACEHOLDER_VALUE = struct.pack(QWORD_FORMAT_SPECIFIER, 0x8BADF00D)
PLACEHOLDER_ARRAY = bytes((
    0x5B, 0x75, 0xBB, 0xE4, 0x9E, 0x18, 0x03, 0x55,
    0x08, 0x4E, 0x3F, 0xE7, 0x60, 0x7E, 0x4F, 0x08,
    0xAA, 0x77, 0x0F, 0x0B, 0xAB, 0xC6, 0x58, 0x5A,
    0xA9, 0x9F, 0x83, 0x4B, 0xD0, 0x6E, 0x67, 0x05))

class ElfFileValueProxy(object):
    """
    Wrapper for a data of arbitrary location, size and type in an ELF file. Unlike pyelftools
    native types, this wrapper class provides an easy way to write updated values back to the
    stream. The data may or may not have an associated symbol. Does not support values within
    compressed sections.

    The following members will always be set:
        elf_file: The pyelftools ELFFile object that the value is part of
        section: The pyselftools Section object that the value is part of
        offset: The offset in the ELF file where the value exists
        length: The length of the value in bytes

    The following members will only be set for value proxies with corresponding symbols.
    For value proxies which do not have symbols (e.g. relocation targets), they will be
    None.
        symbol: The pyelftools Symbol object corresponding to the value
        name: The name of the symbol
    """

    def __init__(self, elf_file, section, offset, vaddr, length, symbol = None, name = None):
        """
        Default initializer
        """

        assert(bool(section.compressed) is False)

        self.elf_file = elf_file
        self.section = section
        self.offset = offset
        self.vaddr = vaddr
        self.length = length
        self.symbol = symbol
        self.name = name


    @classmethod
    def from_vaddr(self, elf_file, vaddr, length):
        """
        Creates an ElfFileValueProxy object from a caller-provided virtual address and length.
        This is useful for creating value proxies for from relocation entries which do not have
        an associated symbol.
        """

        section = None
        for cur_section in elf_file.iter_sections():
            if (cur_section["sh_addr"] < vaddr
                and cur_section["sh_addr"] + cur_section["sh_size"] >= vaddr + length):

                section = cur_section
                break

        assert(section is not None)

        section_offset = vaddr - section["sh_addr"]
        offset = section["sh_offset"] + section_offset

        return ElfFileValueProxy(elf_file, section, offset, vaddr, length)

    @classmethod
    def from_symbol_name(self, elf_file, name):
        """
        Creates an ElfFileValueProxy object by finding the symbol name in the symbol table and mapping
        it to the offset in the file.
        """

        symtab = elf_file.get_section_by_name(".symtab")
        symbols = symtab.get_symbol_by_name(name)
        assert(len(symbols) == 1)
        symbol = symbols[0]

        length = symbol["st_size"]
        section = elf_file.get_section(symbol["st_shndx"])
        assert(section is not None)

        vaddr = symbol["st_value"]
        section_offset = vaddr - section["sh_addr"]
        offset = section["sh_offset"] + section_offset

        return ElfFileValueProxy(elf_file, section, offset, vaddr, length, symbol, name)

    @property
    def value(self):
        self.elf_file.stream.seek(self.offset)
        return self.elf_file.stream.read(self.length)

    @value.setter
    def value(self, value):
        assert(type(value) == bytes)
        assert(len(value) == self.length)

        # The .data() method returns a bytes object. We can't use it to write back to the original
        # buffer, so we need to find the appropriate section within the stream using sh_offset and
        # write to that.
        logging.debug("Writing {} to offset {}".format(value.hex(), hex(self.offset)))
        self.section.stream.seek(self.offset)
        self.section.stream.write(value)

    def set_value(self, format, *args):
        new_value = struct.pack(format, *args)
        assert(len(new_value) == self.length)

        if self.name is not None:
            logging.debug("Changing {} value".format(self.name))

        self.value = new_value

def log_value(var):
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
    log_value(digest)

def process_loadable_segments(elf_file):
    """
    Finds all loadable segments in the module and ensures that the assumptions made by our runtime
    integrity verification code are valid. Returns the list of loadable segments. If an assumption
    is found to be invalid, an exception will be thrown.
    """

    # Find .data and .note.package sections
    note_package_section = elf_file.get_section_by_name(".note.package")
    data_section = elf_file.get_section_by_name(".data")
    if( data_section is None ):
        logging.error("Did not find .data section in elf file!")
        raise RuntimeError

    # Find all loadable segments and calculate their sizes and offsets
    loadable_segments = []
    data_segment = None
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

            if data_segment is not None:
                # There must be exactly one segment containing the .data section, and it must be the
                # last of the PT_LOAD segments
                logging.error("Found loadable segment after segment containing .data section!")
                raise RuntimeError

            if segment["p_flags"] & P_FLAGS.PF_W != 0:
                # Found a writable segment
                if segment.section_in_segment(data_section):
                    # If it contains the data section it should be the last loadable segment
                    data_segment = segment
                elif note_package_section is None or not segment.section_in_segment(note_package_section):
                    logging.error("Found writable segment which does not contain .data or .note.package section!")
                    raise RuntimeError

    data_segment_sections = []
    for section in elf_file.iter_sections():
        if data_segment.section_in_segment(section):
            data_segment_sections.append(section)

    # We set our FIPS module boundary based on where the .data section starts (since it and the
    # .bss section cannot be included in the HMAC). Therefore, .data and .bss must be the second
    # last and last sections of that segment, respectively.
    if data_segment_sections[-2].name != ".data" or \
        data_segment_sections[-1].name != ".bss":
        logging.error("Unexpected section order in segment containing .data section!")
        raise RuntimeError

    return loadable_segments

def overwrite_jump_slots(elf_file, new_value):
    """
    Overwrites the original values of jump slot relocations in the ELF file's stream with the
    given new_value. Returns a list of the original jump slots as tuples of
    (vaddr, original value), so that they can be reset after the HMAC digest is calculated.
    """

    rela_plt_section = elf_file.get_section_by_name(".rela.plt")

    # Jump slot relocations always live in the .rela.plt section. If there is no .rela.plt section,
    # there will be no jump slot relocations
    if rela_plt_section is None:
        return []

    original_jump_slot_values = []
    for relocation in rela_plt_section.iter_relocations():
        relocation_type = relocation["r_info_type"]
        if (relocation_type == ENUM_RELOC_TYPE_x64["R_X86_64_JUMP_SLOT"]
            or relocation_type == ENUM_RELOC_TYPE_AARCH64["R_AARCH64_JUMP_SLOT"]):

            # Note that r_offset is actually a virtual address
            relocation_value = ElfFileValueProxy.from_vaddr(elf_file, relocation["r_offset"], QWORD_BYTE_SIZE)

            original_value_int = struct.unpack(QWORD_FORMAT_SPECIFIER, relocation_value.value)[0]
            original_jump_slot_values.append((relocation_value.vaddr, original_value_int))

            logging.debug("Updating relocation at {} with original value {}".format(
                hex(relocation_value.offset), hex(original_value_int)))

            relocation_value.set_value(QWORD_FORMAT_SPECIFIER, new_value)
        else:
            logging.warning("Unknown relocation type {} found at offset {}".format(
                relocation_type, relocation["r_offset"]))

    return original_jump_slot_values

def reset_jump_slots(elf_file, original_jump_slot_values):
    """
    Resets the jump slot relocations to their original values, which should be given as a list of
    tuples of (vaddr, original value). This must be done after HMACing the module to ensure that
    lazy binding still works.
    """

    for vaddr, original_value in original_jump_slot_values:
        relocation_value = ElfFileValueProxy.from_vaddr(elf_file, vaddr, QWORD_BYTE_SIZE)

        logging.debug("Resetting relocation at {} to original value {}".format(
                hex(vaddr), hex(original_value)))

        relocation_value.set_value(QWORD_FORMAT_SPECIFIER, original_value)

def main():
    """
    Entrypoint
    """

    parser = argparse.ArgumentParser(description = "Postprocess SymCrypt shared object module")
    parser.add_argument("input", type=str, help = "Path to SymCrypt module")
    parser.add_argument("-d", "--debug", action = "store_true",
        help = "Enable debug output (also dumps hashable module contents to file)")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level = logging.DEBUG)
    else:
        logging.basicConfig(level = logging.INFO)

    debug_files_basename = os.path.join(
        os.path.dirname(args.input), "processing", os.path.basename(args.input))
    with open(args.input, "rb") as input_file:
        buffer = input_file.read()
        buffer_stream = io.BytesIO(buffer)

    elf_file = ELFFile(buffer_stream)

    arch = elf_file["e_machine"]
    if not arch == "EM_X86_64" and not arch == "EM_AARCH64":
        logging.error("Unsupported architecture {}".format(arch))
        raise RuntimeError

    original_jump_slot_values = overwrite_jump_slots(elf_file, 0)

    loadable_segments = process_loadable_segments(elf_file)

    # Find the HMAC key placeholder and replace it with a randomly generated key
    key_variable = ElfFileValueProxy.from_symbol_name(elf_file, KEY_NAME)
    assert(key_variable.value == PLACEHOLDER_ARRAY)

    random_key = secrets.token_bytes(len(key_variable.value)) # NB: not actually a secret
    key_variable.set_value(str(len(random_key)) + CHAR_FORMAT_SPECIFIER, random_key)
    log_value(key_variable)

    # Find the HMAC key relative virtual address placeholder and replace it with
    # the actual relative virtual address of the HMAC key
    key_rva_variable = ElfFileValueProxy.from_symbol_name(elf_file, KEY_RVA_NAME)
    assert(key_rva_variable.value == PLACEHOLDER_VALUE)

    key_rva_variable.set_value(QWORD_FORMAT_SPECIFIER, key_variable.vaddr)
    log_value(key_rva_variable)

    # Find the FIPS module boundary placeholder and replace it with the our actual
    # FIPS module boundary, which we have defined to be the start of the .data section
    fips_boundary_variable = ElfFileValueProxy.from_symbol_name(elf_file, BOUNDARY_OFFSET_NAME)
    assert(fips_boundary_variable.value == PLACEHOLDER_VALUE)

    data_section = elf_file.get_section_by_name(".data")
    data_section_offset = data_section["sh_offset"]

    fips_boundary_variable.set_value(QWORD_FORMAT_SPECIFIER, data_section_offset)
    log_value(fips_boundary_variable)

    # Find the HMAC digest placeholder, HMAC the loadable segments of the module, and replace
    # the placeholder with the actual digest
    digest_variable = ElfFileValueProxy.from_symbol_name(elf_file, DIGEST_NAME)
    assert(digest_variable.value == PLACEHOLDER_ARRAY)

    hmac_module(loadable_segments, data_section_offset, key_variable, digest_variable,
        dump_file_path = debug_files_basename + ".loadable.bin" if args.debug else None)

    # Reset the jump slot relocation values to their original values so that lazy binding will
    # still work. We compensate for this at runtime by also overwriting the jump slot values in
    # our in-memory copy of the module with zeros, so the HMAC digests will still match
    if len(original_jump_slot_values) > 0:
        reset_jump_slots(elf_file, original_jump_slot_values)

    # Copy the original input file to a backup file before writing our changes back to the original
    os.replace(args.input, debug_files_basename + ".bak")

    with open(args.input, "wb") as output_file:
        output_file.write(buffer_stream.getbuffer())

    # chmod 0755 the new output file so that it's marked as executable (required by some platforms)
    os.chmod(args.input,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | # User: read, write, execute
        stat.S_IRGRP | stat.S_IXGRP | # Group: read, execute
        stat.S_IXOTH | stat.S_IXOTH) # Other: read, execute

    logging.info("Success!")

if __name__ == "__main__":
    main()