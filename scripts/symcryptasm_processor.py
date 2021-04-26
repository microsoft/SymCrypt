#!/usr/bin/env python3
"""
This script enables processing of symcryptasm files so that they can be assembled in a variety of
environments without requiring forking or duplication of source files - symcryptasm files phrase
assembly in an assembler and environment agnostic way.

The current target assemblers are:
    MASM and GAS
The current target environments are:
    amd64 Windows (using the Microsoft x64 calling convention), and
    amd64 Linux (using the SystemV amd64 calling convention)

Currently we only support functions with up to 6 arguments, and only amd64, but the plan is to
rephrase all remaining .asm in SymCrypt as symcryptasm, extending support as appropriate to enable
this effort.

The processing of symcryptasm files takes place in 2 passes. The first pass is performed by this
symcryptasm_processor.py script, which does the more stateful processing, outputting a .cppasm file.
The .cppasm files are further processed by the C preprocessor to do more simple stateless text
substitutions, outputting a .asm file which can be assembled by the target assembler for the target
environment.

We have set up the intermediate generated files to be created in the output directories in both
razzle and CMake builds.

### symcryptasm syntax ###

Different calling conventions pass arguments to functions in different registers, have differing
numbers of volatile and non-volatile registers, and use the stack in different ways.

We define our own register naming scheme which abstracts away the differences between calling
conventions. The generalities of the naming scheme will be similar across target architectures, but
refer to the Architecture specifics below for details. For the following general information we use
the notation R<n> to denote registers in the symcryptasm register naming scheme.


A leaf function (a function which does not call another function) begins with an invocation of the
FUNCTION_START macro which currently takes 3 arguments:
1) The function name
    This must be the name that matches the corresponding declaration of the function
2) The number of arguments (arg_count) that the function takes
    These arguments will be accessible in some contiguous region of the symcrypt registers at the
    start of the function
        On amd64 this contiguous region is R1..R<arg_count>
    Note: arg_count need not correspond to the exact number of argument in the function declaration
    if the assembly does not use some tail of the arguments
3) The number of registers (reg_count) that the function uses
    These registers will be accessible as R0..R<reg_count-1>

A leaf function ends with the FUNCTION_END macro, which also takes the function name
    (a FUNCTION_END macro's function name must match the preceding FUNCTION_START's name)

At the function start a prologue is generated which arranges the arguments appropriately in
registers, and saves non-volatile registers that have been requested to be used.
At the function end an epilogue is generated with restores the non-volatile registers and returns.


A nested function (a function which does call another function) is specified similarly, only using
NESTED_FUNCTION_START and NESTED_FUNCTION_END macros. A nested function currently updates and aligns
the stack pointer in the function prologue, and avoids use of the redzone in the SystemV ABI.


A macro begins with an invocation of the MACRO_START macro which takes the Macro name, and variable
number of macros argument names. It ends with MACRO_END.

### Architecture specifics ###

### amd64 ###
We allow up to 15 registers to be addressed, with the names:
Q0-Q15 (64-bit registers), W0-W15 (32-bit registers), H0-H15 (16-bit registers), and B0-B15 (8-bit
registers)
Xmm0-Xmm5 registers may be used directly in assembly too, as in both amd64 calling conventions we
currently support, these registers are volatile so do not need any special handling

On function entry we insert a prologue which ensures:
Q0 is the result register (the return value of the function, and the low half of a multiplication)
Q1-Q6 are the first 6 arguments passed to the function

Additionally, there is a special case for functions using mul or mulx instructions, as these
instructions make rdx a special register. Functions using these instructions may address Q0-Q14,
and QH. As rdx is used to pass arguments, its value is moved to another register in the function
prologue. The MUL_FUNCTION_START and MUL_FUNCTION_END macros are used in this case.
    We currently do not support nested mul functions, as we have none of them.

"""

import re
import types
import logging

class Register:
    """A class to represent registers"""

    def __init__(self, name64, name32, name16, name8):
        self.name64 = name64
        self.name32 = name32
        self.name16 = name16
        self.name8  = name8

# amd64 registers
REG_RAX = Register("rax",  "eax",   "ax",   "al")
REG_RBX = Register("rbx",  "ebx",   "bx",   "bl")
REG_RCX = Register("rcx",  "ecx",   "cx",   "cl")
REG_RDX = Register("rdx",  "edx",   "dx",   "dl")
REG_RSI = Register("rsi",  "esi",   "si",  "sil")
REG_RDI = Register("rdi",  "edi",   "di",  "dil")
REG_RSP = Register("rsp",  "esp",   "sp",  "spl")
REG_RBP = Register("rbp",  "ebp",   "bp",  "bpl")
REG_R8  = Register( "r8",  "r8d",  "r8w",  "r8b")
REG_R9  = Register( "r9",  "r9d",  "r9w",  "r9b")
REG_R10 = Register("r10", "r10d", "r10w", "r10b")
REG_R11 = Register("r11", "r11d", "r11w", "r11b")
REG_R12 = Register("r12", "r12d", "r12w", "r12b")
REG_R13 = Register("r13", "r13d", "r13w", "r13b")
REG_R14 = Register("r14", "r14d", "r14w", "r14b")
REG_R15 = Register("r15", "r15d", "r15w", "r15b")

class CallingConvention:
    """A class to represent calling conventions"""

    def __init__(self, name, architecture, mapping, argument_registers, volatile_registers, gen_prologue_fn, gen_epilogue_fn, gen_get_memslot_offset_fn):
        self.name = name
        self.architecture = architecture
        self.mapping = mapping
        self.argument_registers = argument_registers
        self.volatile_registers = volatile_registers
        self.gen_prologue_fn = types.MethodType(gen_prologue_fn, self)
        self.gen_epilogue_fn = types.MethodType(gen_epilogue_fn, self)
        self.gen_get_memslot_offset_fn = types.MethodType(gen_get_memslot_offset_fn, self)


def get_mul_mapping_from_normal_mapping(mapping, argument_registers):
    """Gets the register mapping used in functions requiring special rdx handling.

    In amd64, when using mul and mulx, rdx is a special register.
    rdx is also used for passing arguments in both Msft and System V calling conventions.
    In asm functions that use mul or mulx, we will explicitly move the argument passed in
    rdx to a different volatile register in the function prologue, and in the function body
    we refer to rdx using (Q|D|W|B)H.
    """
    rdx_index = None
    return_mapping = { 'H': REG_RDX }
    for (index, register) in mapping.items():
        if register == REG_RDX:
            rdx_index = index
            break
    for (index, register) in mapping.items():
        # preserve argument registers
        if (index <= argument_registers) and (index != rdx_index):
            return_mapping[index] = register
        # replace rdx with the first non-argument register
        if index == argument_registers+1:
            return_mapping[rdx_index] = register
        # shuffle all later registers down to fill the gap
        if index > argument_registers+1:
            return_mapping[index-1] = register
    return return_mapping

# Calling convention constants

MAX_FUNCTION_ARGUMENT_COUNT = 6 # restrict to 6 arguments for now
MAX_FUNCTION_REGISTER_COUNT = 15

# Microsoft x64 calling convention
MAPPING_AMD64_MSFT = {
    0: REG_RAX, # Result register
    1: REG_RCX, # Argument 1 / volatile
    2: REG_RDX, # Argument 2 / volatile
    3: REG_R8,  # Argument 3 / volatile
    4: REG_R9,  # Argument 4 / volatile
    5: REG_R10, # volatile
    6: REG_R11, # volatile
    7: REG_RSI, # All registers from rsi are non-volatile and need to be saved/restored in epi/prologue
    8: REG_RDI,
    9: REG_RBP,
    10:REG_RBX,
    11:REG_R12,
    12:REG_R13,
    13:REG_R14,
    14:REG_R15,
    # currently not mapping rsp
}

def calc_amd64_shadow_space_allocation_size(self, reg_count):
    # If we are a nested function, we must allocate 32B of shadow space on the stack, and ensure the
    # stack pointer is aligned to 16B
    # Before the prologue we have rsp % 16 == 8 - as the call pushed an 8B return address on an
    # aligned stack
    alignment = 8
    # We then pushed some number of additional 8B registers onto the stack
    if reg_count > self.volatile_registers:
        alignment = (alignment + (8 * (self.volatile_registers - reg_count))) % 16
    shadow_space_allocation_size = 32
    if alignment == 8:
        # possibly allocate 8 more bytes to align the stack to 16B
        shadow_space_allocation_size += 8
    return shadow_space_allocation_size

def gen_prologue_amd64_msft(self, arg_count, reg_count, mul_fixup="", nested=False):
    prologue = "\n"
    if reg_count > self.volatile_registers:
        prologue += "rex_push_reg Q%s\n" % self.volatile_registers
        for i in range(self.volatile_registers+1, reg_count):
            prologue += "push_reg Q%s\n" % i
        prologue += "\nEND_PROLOGUE\n\n"

    shadow_space_allocation_size = 0

    if nested:
        shadow_space_allocation_size = calc_amd64_shadow_space_allocation_size(self, reg_count)
        prologue += "sub rsp, %d // allocate shadow space and align stack\n\n" % shadow_space_allocation_size

    prologue += mul_fixup

    # put additional arguments into Q5-Q6 (we do not support more than 6 (MAX_FUNCTION_ARGUMENT_COUNT) arguments for now)
    # stack_offset to get the 5th argument is:
    # 32B of shadow space + 8B for return address + (8*#pushed registers in prologue) + shadow_space_allocation_size
    stack_offset = 32 + 8 + (8*(reg_count-self.volatile_registers)) + shadow_space_allocation_size
    for i in range(self.argument_registers+1, min(arg_count+1, MAX_FUNCTION_ARGUMENT_COUNT+1)):
        prologue += "mov Q%s, [rsp + %d]\n" % (i, stack_offset)
        stack_offset += 8
    return prologue

def gen_prologue_amd64_msft_mul(self, arg_count, reg_count):
    return gen_prologue_amd64_msft(self, arg_count, reg_count, "mov Q2, QH\n")

def gen_prologue_amd64_msft_nested(self, arg_count, reg_count):
    return gen_prologue_amd64_msft(self, arg_count, reg_count, "", nested=True)

def gen_epilogue_amd64_msft(self, arg_count, reg_count, nested=False):
    epilogue = ""

    if nested:
        shadow_space_allocation_size = calc_amd64_shadow_space_allocation_size(self, reg_count)
        epilogue += "add rsp, %d // deallocate shadow space and align stack\n\n" % shadow_space_allocation_size

    if reg_count > self.volatile_registers:
        epilogue += "BEGIN_EPILOGUE\n"
        for i in reversed(range(self.volatile_registers, reg_count)):
            epilogue += "pop Q%s\n" % i
    epilogue += "ret\n"
    return epilogue

def gen_epilogue_amd64_msft_nested(self, arg_count, reg_count):
    return gen_epilogue_amd64_msft(self, arg_count, reg_count, nested=True)

def gen_get_memslot_offset_amd64_msft(self, slot, arg_count, reg_count, nested=False):
    # only support 4 memory slots for now (in shadow space)
    if(slot >= 4):
        logging.error("Symcryptasm currently only support 4 memory slots! (requested slot%d)" % slot)
        exit(1)
    # 8B for return address + (8*#pushed registers in prologue)
    stack_offset = 8 + (8*(reg_count-self.volatile_registers))
    if nested:
        stack_offset += calc_amd64_shadow_space_allocation_size(self, reg_count)
    return "%d /*MEMSLOT%d*/" % (stack_offset+(8*slot), slot)

def gen_get_memslot_offset_amd64_msft_nested(self, slot, arg_count, reg_count):
    return gen_get_memslot_offset_amd64_msft(self, slot, arg_count, reg_count, nested=True)

CALLING_CONVENTION_AMD64_MSFT = CallingConvention(
    "msft_x64", "amd64", MAPPING_AMD64_MSFT, 4, 7,
    gen_prologue_amd64_msft, gen_epilogue_amd64_msft, gen_get_memslot_offset_amd64_msft)
CALLING_CONVENTION_AMD64_MSFT_MUL = CallingConvention(
    "msft_x64", "amd64", get_mul_mapping_from_normal_mapping(MAPPING_AMD64_MSFT, 4), 4, 6,
    gen_prologue_amd64_msft_mul, gen_epilogue_amd64_msft, gen_get_memslot_offset_amd64_msft)
CALLING_CONVENTION_AMD64_MSFT_NESTED = CallingConvention(
    "msft_x64", "amd64", MAPPING_AMD64_MSFT, 4, 7,
    gen_prologue_amd64_msft_nested, gen_epilogue_amd64_msft_nested, gen_get_memslot_offset_amd64_msft_nested)

# AMD64 System V calling convention
MAPPING_AMD64_SYSTEMV = {
    0: REG_RAX, # Result register
    1: REG_RDI, # Argument 1 / volatile
    2: REG_RSI, # Argument 2 / volatile
    3: REG_RDX, # Argument 3 / volatile
    4: REG_RCX, # Argument 4 / volatile
    5: REG_R8,  # Argument 5 / volatile
    6: REG_R9,  # Argument 6 / volatile
    7: REG_R10, # volatile
    8: REG_R11, # volatile
    9: REG_RBX, # All registers from rbx are non-volatile and need to be saved/restored in epi/prologue
    10:REG_RBP,
    11:REG_R12,
    12:REG_R13,
    13:REG_R14,
    14:REG_R15
    # currently not mapping rsp
}

def gen_prologue_amd64_systemv(self, arg_count, reg_count, mul_fixup="", nested=False):
    # push volatile registers onto the stack
    prologue = "\n"
    if reg_count > self.volatile_registers:
        for i in range(self.volatile_registers, reg_count):
            prologue += "push Q%s\n" % i

    # If we are a nested function, we need to align the stack to 16B, and allocate space for up to 4
    # memory slots not in the redzone. We can use the same logic as on the MSFT x64 side to allocate
    # our own space for 32B of local variables (whereas on the MSFT side, we use this for allocating
    # space for a function we are about to call)
    if nested:
        allocation_size = calc_amd64_shadow_space_allocation_size(self, reg_count)
        prologue += "sub rsp, %d // allocate memslot space and align stack\n\n" % allocation_size

    prologue += mul_fixup

    # do not support more than 6 (MAX_FUNCTION_ARGUMENT_COUNT) arguments for now
    # # put additional arguments into Q7-Qn
    # # stack_offset to get the 7th argument is:
    # # 8B for return address
    # stack_offset = 8
    # for i in range(self.argument_registers+1, arg_count+1):
    #     prologue += "mov Q%s, [rsp + %d]\n" % (i, stack_offset)
    #     stack_offset += 8

    return prologue

def gen_prologue_amd64_systemv_mul(self, arg_count, reg_count):
    return gen_prologue_amd64_systemv(self, arg_count, reg_count, "mov Q3, QH\n")

def gen_prologue_amd64_systemv_nested(self, arg_count, reg_count):
    return gen_prologue_amd64_systemv(self, arg_count, reg_count, "", nested=True)

def gen_epilogue_amd64_systemv(self, arg_count, reg_count, nested=False):
    epilogue = ""

    if nested:
        allocation_size = calc_amd64_shadow_space_allocation_size(self, reg_count)
        epilogue += "add rsp, %d // deallocate memslot space and align stack\n\n" % allocation_size

    if reg_count > self.volatile_registers:
        for i in reversed(range(self.volatile_registers, reg_count)):
            epilogue += "pop Q%s\n" % i
    epilogue += "ret\n"
    return epilogue

def gen_epilogue_amd64_systemv_nested(self, arg_count, reg_count):
    return gen_epilogue_amd64_systemv(self, arg_count, reg_count, nested=True)

def gen_get_memslot_offset_amd64_systemv(self, slot, arg_count, reg_count, nested=False):
    # only support 4 memory slots for now
    if(slot >= 4):
        logging.error("Symcryptasm currently only support 4 memory slots! (requested slot%d)" % slot)
        exit(1)
    # For leaf functions, use the top of the redzone below the stack pointer
    offset = -8 * (slot+1)
    if nested:
        # For nested functions, use the 32B of memslot space above the stack pointer created in the prologue
        offset = 8*slot
    return "%d /*MEMSLOT%d*/" % (offset, slot)

def gen_get_memslot_offset_amd64_systemv_nested(self, slot, arg_count, reg_count):
    return gen_get_memslot_offset_amd64_systemv(self, slot, arg_count, reg_count, nested=True)

CALLING_CONVENTION_AMD64_SYSTEMV = CallingConvention(
    "amd64_systemv", "amd64", MAPPING_AMD64_SYSTEMV, 6, 9,
    gen_prologue_amd64_systemv, gen_epilogue_amd64_systemv, gen_get_memslot_offset_amd64_systemv)
CALLING_CONVENTION_AMD64_SYSTEMV_MUL = CallingConvention(
    "amd64_systemv", "amd64", get_mul_mapping_from_normal_mapping(MAPPING_AMD64_SYSTEMV, 6), 6, 8,
    gen_prologue_amd64_systemv_mul, gen_epilogue_amd64_systemv, gen_get_memslot_offset_amd64_systemv)
CALLING_CONVENTION_AMD64_SYSTEMV_NESTED = CallingConvention(
    "amd64_systemv", "amd64", MAPPING_AMD64_SYSTEMV, 6, 9,
    gen_prologue_amd64_systemv_nested, gen_epilogue_amd64_systemv_nested, gen_get_memslot_offset_amd64_systemv_nested)


def gen_function_start_defines(mapping, arg_count, reg_count):
    defines = ""
    for (index, reg) in mapping.items():
        if (index != 'H') and (index >= max(arg_count+1, reg_count)):
            continue
        defines += "#define Q%s %s\n" % (index, reg.name64)
        defines += "#define D%s %s\n" % (index, reg.name32)
        defines += "#define W%s %s\n" % (index, reg.name16)
        defines += "#define B%s %s\n" % (index, reg.name8)
    return defines

def gen_function_end_defines(mapping, arg_count, reg_count):
    undefs = ""
    for (index, _) in mapping.items():
        if (index != 'H') and (index >= max(arg_count+1, reg_count)):
            continue
        undefs += "#undef Q%s\n" % (index)
        undefs += "#undef D%s\n" % (index)
        undefs += "#undef W%s\n" % (index)
        undefs += "#undef B%s\n" % (index)
    return undefs

MASM_FRAMELESS_FUNCTION_ENTRY   = "LEAF_ENTRY %s, _TEXT\n"
MASM_FRAMELESS_FUNCTION_END     = "LEAF_END %s, _TEXT\n"
MASM_FRAME_FUNCTION_ENTRY       = "NESTED_ENTRY %s, _TEXT\n"
MASM_FRAME_FUNCTION_END         = "NESTED_END %s, _TEXT\n"

GAS_FUNCTION_ENTRY    = "%s: .global %s\n"
GAS_FUNCTION_END      = ""

def generate_prologue(assembler, calling_convention, function_name, arg_count, reg_count, nested):
    function_entry = None
    if assembler == "masm":
        # need to identify and mark up frame functions in masm
        if nested or (reg_count > calling_convention.volatile_registers):
            function_entry = MASM_FRAME_FUNCTION_ENTRY % (function_name)
        else:
            function_entry = MASM_FRAMELESS_FUNCTION_ENTRY % (function_name)
    elif assembler == "gas":
        function_entry = GAS_FUNCTION_ENTRY % (function_name, function_name)

    prologue = gen_function_start_defines(calling_convention.mapping, arg_count, reg_count)
    prologue += "%s" % (function_entry)
    prologue += calling_convention.gen_prologue_fn(arg_count, reg_count)

    return prologue

def generate_epilogue(assembler, calling_convention, function_name, arg_count, reg_count, nested):
    function_end = None
    if assembler == "masm":
        # need to identify and mark up frame functions in masm
        if nested or (reg_count > calling_convention.volatile_registers):
            function_end = MASM_FRAME_FUNCTION_END % (function_name)
        else:
            function_end = MASM_FRAMELESS_FUNCTION_END % (function_name)
    elif assembler == "gas":
        function_end = GAS_FUNCTION_END

    epilogue = calling_convention.gen_epilogue_fn(arg_count, reg_count)
    epilogue += "%s" % (function_end)
    epilogue += gen_function_end_defines(calling_convention.mapping, arg_count, reg_count)

    return epilogue

MASM_MACRO_START    = "%s MACRO %s\n"
MASM_MACRO_END      = "ENDM\n"
GAS_MACRO_START     = ".macro %s %s\n"
GAS_MACRO_END       = ".endm\n"
MASM_ALTERNATE_ENTRY= "ALTERNATE_ENTRY %s\n"
GAS_ALTERNATE_ENTRY = "%s: .global %s\n"


FUNCTION_START_PATTERN  = re.compile("\s*(NESTED_)?(MUL_)?FUNCTION_START\s*\(\s*([a-zA-Z0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)")
FUNCTION_END_PATTERN    = re.compile("\s*(NESTED_)?(MUL_)?FUNCTION_END\s*\(\s*([a-zA-Z0-9]+)\s*\)")
GET_MEMSLOT_PATTERN     = re.compile("GET_MEMSLOT_OFFSET\s*\(\s*slot([0-9]+)\s*\)")
ALTERNATE_ENTRY_PATTERN = re.compile("\s*ALTERNATE_ENTRY\s*\(\s*([a-zA-Z0-9]+)\s*\)")
MACRO_START_PATTERN     = re.compile("\s*MACRO_START\s*\(\s*([A-Z_0-9]+)\s*,([^\)]+)\)")
MACRO_END_PATTERN       = re.compile("\s*MACRO_END\s*\(\s*\)")

class ProcessingStateMachine:
    """A class to hold the state when processing a file and handle files line by line"""

    def __init__(self, assembler, normal_calling_convention, mul_calling_convention, nested_calling_convention):
        self.assembler = assembler
        self.normal_calling_convention = normal_calling_convention
        self.mul_calling_convention = mul_calling_convention
        self.nested_calling_convention = nested_calling_convention

        self.function_start_match = None
        self.function_start_line = 0
        self.is_nested_function = None
        self.is_mul_function = None
        self.calling_convention = None
        self.function_name = None
        self.arg_count = None
        self.reg_count = None

        self.macro_start_match = None
        self.macro_name = None
        self.macro_args = None

    def process_line(self, line, line_num):
        if self.function_start_match == None and self.macro_start_match == None:
            return self.process_normal_line(line, line_num)
        elif self.function_start_match != None:
            return self.process_function_line(line, line_num)
        elif self.macro_start_match != None:
            return self.process_macro_line(line, line_num)
        else:
            logging.error("Whoops, something is broken with the state machine (failed at line %d)" % line_num)
            exit(1)

    def process_normal_line(self, line, line_num):
        # Not currently in a function or macro
        match = FUNCTION_START_PATTERN.match(line)
        if (match):
            return self.process_start_function(match, line, line_num)

        match = MACRO_START_PATTERN.match(line)
        if (match):
            return self.process_start_macro(match, line, line_num)

        # Not starting a function or a macro
        return line

    def process_start_function(self, match, line, line_num):
        # Entering a new function
        self.function_start_match = match
        self.function_start_line = line_num
        self.is_nested_function = (match.group(1) == "NESTED_")
        self.is_mul_function = (match.group(2) == "MUL_")
        self.function_name = match.groups()[-3]
        self.arg_count = int(match.groups()[-2])
        self.reg_count = int(match.groups()[-1])

        if self.is_nested_function and self.is_mul_function:
            logging.error(
                "Too many prefixes for symcryptasm function - currently only 1 of prefix, MUL_ or NESTED_, is supported!\n\t"
                "%s (line %d)"
                % (line, line_num))
            exit(1)
        if self.arg_count > MAX_FUNCTION_ARGUMENT_COUNT:
            logging.error(
                "Too many (%d) arguments for symcryptasm function - currently only %d arguments are supported!\n\t"
                "%s (line %d)"
                % (self.arg_count, MAX_FUNCTION_ARGUMENT_COUNT, match.group(0), line_num))
            exit(1)
        if self.reg_count > MAX_FUNCTION_REGISTER_COUNT:
            logging.error(
                "Too many (%d) registers required for symcryptasm function - only %d registers are supported!\n\t"
                "%s (line %d)"
                % (self.reg_count, MAX_FUNCTION_REGISTER_COUNT, match.group(0), line_num))
            exit(1)
        if self.is_mul_function and self.reg_count > MAX_FUNCTION_REGISTER_COUNT-1:
            logging.error(
                "Too many (%d) registers required for symcryptasm mul function - only %d registers are supported!\n\t"
                "%s (line %d)"
                % (self.reg_count, MAX_FUNCTION_REGISTER_COUNT-1, match.group(0), line_num))
            exit(1)

        logging.info("%d: function start %s, %d, %d" % (line_num, self.function_name, self.arg_count, self.reg_count))

        if self.is_nested_function:
            self.calling_convention = self.nested_calling_convention
        elif self.is_mul_function:
            self.calling_convention = self.mul_calling_convention
        else:
            self.calling_convention = self.normal_calling_convention

        return generate_prologue(self.assembler, self.calling_convention, self.function_name, self.arg_count, self.reg_count, self.is_nested_function)

    def process_start_macro(self, match, line, line_num):
        self.macro_start_match = match
        self.macro_name = match.group(1)
        self.macro_args = [ x.strip() for x in match.group(2).split(",") ]

        logging.info("%d: macro start %s, %s" % (line_num, self.macro_name, self.macro_args))

        if self.assembler == "masm":
            return MASM_MACRO_START % (self.macro_name, match.group(2))
        elif self.assembler == "gas":
            return GAS_MACRO_START % (self.macro_name, match.group(2))

    def process_function_line(self, line, line_num):
        # Currently in a function

        match = ALTERNATE_ENTRY_PATTERN.match(line)
        if (match):
            if self.assembler == "masm":
                return MASM_ALTERNATE_ENTRY % match.group(1)
            elif self.assembler == "gas":
                return GAS_ALTERNATE_ENTRY % (match.group(1), match.group(1))

        match = FUNCTION_END_PATTERN.match(line)
        if (match):
            # Check the end function has same prefix as previous start function
            if  (self.is_nested_function ^ (match.group(1) == "NESTED_")) or \
                (self.is_mul_function ^ (match.group(2) == "MUL_")):
                logging.error("Function start and end do not have same MUL_ or NESTED_ prefix!\n\tStart: %s (line %d)\n\tEnd:   %s (line %d)"
                    % (self.function_start_match.group(0), self.function_start_line, match.group(0), line_num))
                exit(1)
            # Check the end function pattern has the same label as the previous start function pattern
            if self.function_name != match.groups()[-1]:
                logging.error("Function start label does not match Function end label!\n\tStart: %s (line %d)\n\tEnd:   %s (line %d)"
                    % (self.function_name, self.function_start_line, match.groups()[-1], line_num))
                exit(1)

            epilogue = generate_epilogue(self.assembler, self.calling_convention, self.function_name, self.arg_count, self.reg_count, self.is_nested_function)

            logging.info("%d: function end %s" % (line_num, self.function_name))

            self.function_start_match = None
            self.function_start_line = 0
            self.is_nested_function = None
            self.is_mul_function = None
            self.calling_convention = None
            self.function_name = None
            self.arg_count = None
            self.reg_count = None

            return epilogue

        # replace any GET_MEMSLOT_OFFSET macros in line
        match = GET_MEMSLOT_PATTERN.search(line)
        while(match):
            slot = int(match.group(1))
            replacement = self.calling_convention.gen_get_memslot_offset_fn(slot, self.arg_count, self.reg_count)
            line = GET_MEMSLOT_PATTERN.sub(replacement, line)
            match = GET_MEMSLOT_PATTERN.search(line)

            logging.info("%d: memslot macro %d" % (line_num, slot))

        # Not modifying the line any further
        return line

    def process_macro_line(self, line, line_num):
        # Currently in a macro
        match = MACRO_END_PATTERN.match(line)
        if (match):
            logging.info("%d: macro end %s" % (line_num, self.macro_name))

            self.macro_start_match = None
            self.macro_name = None
            self.macro_args = None

            if self.assembler == "masm":
                return MASM_MACRO_END
            elif self.assembler == "gas":
                return GAS_MACRO_END

        if self.assembler == "gas":
            # In GAS macros we need to escape all of the macro arguments with a backslash in the macro body
            for arg in self.macro_args:
                line = re.sub(arg, r"\\%s" % arg, line)

        # Not modifying the line any further
        return line

def process_file(target, infilename, outfilename):
    assembler = None
    if target == "masm":
        assembler = "masm"
        normal_calling_convention = CALLING_CONVENTION_AMD64_MSFT
        mul_calling_convention = CALLING_CONVENTION_AMD64_MSFT_MUL
        nested_calling_convention = CALLING_CONVENTION_AMD64_MSFT_NESTED
    elif target == "gas":
        assembler = "gas"
        normal_calling_convention = CALLING_CONVENTION_AMD64_SYSTEMV
        mul_calling_convention = CALLING_CONVENTION_AMD64_SYSTEMV_MUL
        nested_calling_convention = CALLING_CONVENTION_AMD64_SYSTEMV_NESTED

    # iterate through file line by line in one pass
    file_processing_state = ProcessingStateMachine(
        assembler, normal_calling_convention, mul_calling_convention, nested_calling_convention)

    with open(infilename) as infile:
        with open(outfilename, "w") as outfile:
            for line_num, line in enumerate(infile):
                processed_line = file_processing_state.process_line(line, line_num)
                outfile.write(processed_line)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Preprocess symcryptasm into files that will be further processed with C preprocessor to generate MASM or GAS")
    parser.add_argument('target', type=str, help='Target that we want to preprocess for')
    parser.add_argument('inputfile', type=str, help='Path to input file')
    parser.add_argument('outputfile', type=str, help='Path to output file')

    args = parser.parse_args()
    process_file(args.target, args.inputfile, args.outputfile)
