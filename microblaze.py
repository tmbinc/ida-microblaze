# ----------------------------------------------------------------------
# IDA Pro Microblaze processor module
import sys
import idaapi
from idaapi import *

def is_reg(op, reg):
    return op.type == o_reg and op.reg == reg

def fix_sign_32(l):
    l &= 0xFFFFFFFF
    if l & 0x80000000:
        l -= 0x100000000
    return l

# ----------------------------------------------------------------------
class microblaze_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['microblaze']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Xilinx Microblaze']

    # register names
    reg_names = [
        # General purpose registers
        "r0",
        "r1",
        "r2",
        "r3",
        "r4",
        "r5",
        "r6",
        "r7",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "r16",
        "r17",
        "r18",
        "r19",
        "r20",
        "r21",
        "r22",
        "r23",
        "r24",
        "r25",
        "r26",
        "r27",
        "r28",
        "r29",
        "r30",
        "r31", # 31
        "PC",  # 32
        "MSR", # 33
        "EAR",
        "ESR",
        "BTR",
        "FSR",
        "EDR",
        "SLR",
        "SHR",
        "PID",
        "ZPR",
        "TLBHI",
        "TLBX",
        "TLBSX",
        "PVR0",
        "CS",  # 47
        "DS",  # 48
    ]

    special_regs = {
        0x0000: "PC",
        0x0001: "MSR",
        0x0003: "EAR",
        0x0005: "ESR",
        0x0007: "FSR",
        0x000B: "BTR",
        0x000D: "EDR",
        0x0800: "SLR",
        0x0802: "SHR",
        0x1000: "PID",
        0x1001: "ZPR",
        0x1002: "TLBX",
        0x1003: "TLBLO",
        0x1004: "TLBHI",
        0x2000: "PVR0",
        0x2001: "PVR1",
        0x2002: "PVR2",
        0x2003: "PVR3",
        0x2004: "PVR4",
        0x2005: "PVR5",
        0x2006: "PVR6",
        0x2007: "PVR7",
        0x2008: "PVR8",
        0x2009: "PVR9",
        0x200A: "PVR10",
        0x200B: "PVR11",
    }

    # number of registers (optional: deduced from the len(reg_names))
    regs_num = len(reg_names)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 47 # index of CS
    reg_last_sreg  = 48 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    reg_code_sreg = 47
    reg_data_sreg = 48

    # Array of typical code start sequences (optional)
    codestart = []

    # Array of 'return' instruction opcodes (optional)
    retcodes = []

    # Array of instructions
    instruc = [
        {'name': 'add', 'value': 0x00000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'rsub', 'value': 0x04000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'addc', 'value': 0x08000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'rsubc', 'value': 0x0c000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'addk', 'value': 0x10000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'rsubk', 'value': 0x14000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'cmp', 'value': 0x14000001, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'cmpu', 'value': 0x14000003, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'addkc', 'value': 0x18000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'raddkc', 'value': 0x18000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'rsubkc', 'value': 0x1c000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'addi', 'value': 0x20000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'rsubi', 'value': 0x24000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'addic', 'value': 0x28000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'rsubic', 'value': 0x2c000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'addik', 'value': 0x30000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'rsubik', 'value': 0x34000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'addikc', 'value': 0x38000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'rsubikc', 'value': 0x3c000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'mul', 'value': 0x40000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'mulh', 'value': 0x40000001, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'mulhu', 'value': 0x40000003, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'mulhsu', 'value': 0x40000002, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'bsrl', 'value': 0x44000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'bsra', 'value': 0x44000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'bsll', 'value': 0x44000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'idiv', 'value': 0x48000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'idivu', 'value': 0x48000002, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'tneagetd', 'value': 0x4c000000, 'mask': 0xfc1f0000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000201}, #  !!!!!
        {'name': 'tnaputd', 'value': 0x4c000000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #  !!!!!
        {'name': 'tnecagetd', 'value': 0x4c000000, 'mask': 0xfc1f0000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000201}, #  !!!!!
        {'name': 'tncaputd', 'value': 0x4c000000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #  !!!!!
        {'name': 'fadd', 'value': 0x58000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'frsub', 'value': 0x58000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fmul', 'value': 0x58000100, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fdiv', 'value': 0x58000180, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.un', 'value': 0x58000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.lt', 'value': 0x58000210, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.eq', 'value': 0x58000220, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.le', 'value': 0x58000230, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.gt', 'value': 0x58000240, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.ne', 'value': 0x58000250, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'fcmp.ge', 'value': 0x58000260, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'flt', 'value': 0x58000280, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'fint', 'value': 0x58000300, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'fsqrt', 'value': 0x58000380, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'muli', 'value': 0x60000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'bsrli', 'value': 0x64000000, 'mask': 0xfc00ffe0, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40040101}, #
        {'name': 'bsrai', 'value': 0x64000200, 'mask': 0xfc00ffe0, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40040101}, #
        {'name': 'bslli', 'value': 0x64000400, 'mask': 0xfc00ffe0, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40040101}, #
        {'name': 'bsefi', 'value': 0x64004000, 'mask': 0xfc00f820, 'feature': CF_USE1|CF_USE2|CF_USE3|CF_USE4, 'flags': 0x40180101}, #
        {'name': 'tneaget', 'value': 0x6c000000, 'mask': 0xfc1f0000, 'feature': CF_USE1, 'flags': 0x40000001}, #  !!!!!
        {'name': 'tnaput', 'value': 0x6c000000, 'mask': 0xffe00000, 'feature': CF_USE1, 'flags': 0x40000008}, #  !!!!!
        {'name': 'tnecaget', 'value': 0x6c000000, 'mask': 0xfc1f0000, 'feature': CF_USE1, 'flags': 0x40000001}, #  !!!!!
        {'name': 'tncaput', 'value': 0x6c000000, 'mask': 0xffe00000, 'feature': CF_USE1, 'flags': 0x40000008}, #  !!!!!
        {'name': 'or', 'value': 0x80000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'pcmpbf', 'value': 0x80000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'and', 'value': 0x84000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'xor', 'value': 0x88000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'pcmpeq', 'value': 0x88000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'andn', 'value': 0x8c000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'pcmpne', 'value': 0x8c000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sra', 'value': 0x90000001, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'src', 'value': 0x90000021, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'srl', 'value': 0x90000041, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'sext8', 'value': 0x90000060, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'sext16', 'value': 0x90000061, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'clz', 'value': 0x900000e0, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'swapb', 'value': 0x900001e0, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'swaph', 'value': 0x900001e2, 'mask': 0xfc00ffff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000101}, #
        {'name': 'wic', 'value': 0x90000068, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'wdc', 'value': 0x90000064, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'wdc.flush', 'value': 0x90000074, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'wdc.clear', 'value': 0x90000066, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'wdc.clear.ea', 'value': 0x900000e6, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'mts', 'value': 0x9400c000, 'mask': 0xffe0c000, 'feature': CF_USE1, 'flags': 0x4000000c}, #
        {'name': 'mfs', 'value': 0x94008000, 'mask': 0xfc1fc000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000401}, #
        {'name': 'mfse', 'value': 0x94088000, 'mask': 0xfc1fc000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000401}, #
        {'name': 'msrclr', 'value': 0x94010000, 'mask': 0xfc1fc000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000801}, #
        {'name': 'msrset', 'value': 0x94000000, 'mask': 0xfc1fc000, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000801}, #
        {'name': 'br', 'value': 0x98000000, 'mask': 0xffff07ff, 'feature': CF_USE1|CF_STOP, 'flags': 0x40000010}, #
        {'name': 'brd', 'value': 0x98100000, 'mask': 0xffff07ff, 'feature': CF_USE1|CF_STOP, 'flags': 0x40000010}, #
        {'name': 'brld', 'value': 0x98140000, 'mask': 0xfc1f07ff, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x40000201}, #
        {'name': 'bra', 'value': 0x98080000, 'mask': 0xffff07ff, 'feature': CF_USE1|CF_STOP, 'flags': 0x40000010}, #
        {'name': 'brad', 'value': 0x98180000, 'mask': 0xffff07ff, 'feature': CF_USE1|CF_STOP, 'flags': 0x40000010}, #
        {'name': 'brald', 'value': 0x981c0000, 'mask': 0xfc1f07ff, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x40000201}, #
        {'name': 'brk', 'value': 0x980c0000, 'mask': 0xfc1f07ff, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x40000201}, #
        {'name': 'beq', 'value': 0x9c000000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bne', 'value': 0x9c200000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'blt', 'value': 0x9c400000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'ble', 'value': 0x9c600000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bgt', 'value': 0x9c800000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bge', 'value': 0x9ca00000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'beqd', 'value': 0x9e000000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bned', 'value': 0x9e200000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bltd', 'value': 0x9e400000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bled', 'value': 0x9e600000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bgtd', 'value': 0x9e800000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'bged', 'value': 0x9ea00000, 'mask': 0xffe007ff, 'feature': CF_USE1|CF_USE2, 'flags': 0x40000208}, #
        {'name': 'ori', 'value': 0xa0000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'andi', 'value': 0xa4000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'xori', 'value': 0xa8000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'andni', 'value': 0xac000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'imm', 'value': 0xb0000000, 'mask': 0xffff0000, 'feature': CF_USE1, 'flags': 0x40000002}, #
        {'name': 'rtsd', 'value': 0xb6000000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2|CF_STOP, 'flags': 0x50001008}, #
        {'name': 'rtid', 'value': 0xb6200000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2|CF_STOP, 'flags': 0x50001008}, #
        {'name': 'rtbd', 'value': 0xb6400000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2|CF_STOP, 'flags': 0x50001008}, #
        {'name': 'rted', 'value': 0xb6800000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2|CF_STOP, 'flags': 0x50001008}, #
        {'name': 'bri', 'value': 0xb8000000, 'mask': 0xffff0000, 'feature': CF_USE1|CF_STOP, 'flags': 0x70000002}, #
        {'name': 'mbar', 'value': 0xb8020004, 'mask': 0xfc1fffff, 'feature': CF_USE1|CF_STOP, 'flags': 0x40000020}, #
        {'name': 'brid', 'value': 0xb8100000, 'mask': 0xffff0000, 'feature': CF_USE1|CF_STOP, 'flags': 0x70000002}, #
        {'name': 'brlid', 'value': 0xb8140000, 'mask': 0xfc1f0000, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x70001001}, #
        {'name': 'brai', 'value': 0xb8080000, 'mask': 0xffff0000, 'feature': CF_USE1|CF_STOP, 'flags': 0x50000002}, #
        {'name': 'braid', 'value': 0xb8180000, 'mask': 0xffff0000, 'feature': CF_USE1|CF_STOP, 'flags': 0x50000002}, #
        {'name': 'bralid', 'value': 0xb81c0000, 'mask': 0xfc1f0000, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x50001001}, #
        {'name': 'brki', 'value': 0xb80c0000, 'mask': 0xfc1f0000, 'feature': CF_USE1|CF_USE2|CF_CALL, 'flags': 0x50001001}, #
        {'name': 'beqi', 'value': 0xbc000000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bnei', 'value': 0xbc200000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'blti', 'value': 0xbc400000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'blei', 'value': 0xbc600000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bgti', 'value': 0xbc800000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bgei', 'value': 0xbca00000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'beqid', 'value': 0xbe000000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bneid', 'value': 0xbe200000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bltid', 'value': 0xbe400000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bleid', 'value': 0xbe600000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bgtid', 'value': 0xbe800000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'bgeid', 'value': 0xbea00000, 'mask': 0xffe00000, 'feature': CF_USE1|CF_USE2, 'flags': 0x70001008}, #
        {'name': 'lbu', 'value': 0xc0000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lbur', 'value': 0xc0000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lbuea', 'value': 0xc0000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lhu', 'value': 0xc4000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lhur', 'value': 0xc4000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lhuea', 'value': 0xc4000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lw', 'value': 0xc8000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lwr', 'value': 0xc8000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lwx', 'value': 0xc8000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lwea', 'value': 0xc8000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sb', 'value': 0xd0000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sbr', 'value': 0xd0000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sbea', 'value': 0xd0000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sh', 'value': 0xd4000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'shr', 'value': 0xd4000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'shea', 'value': 0xd4000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'sw', 'value': 0xd8000000, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'swr', 'value': 0xd8000200, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'swx', 'value': 0xd8000400, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'swea', 'value': 0xd8000080, 'mask': 0xfc0007ff, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x40010101}, #
        {'name': 'lbui', 'value': 0xe0000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'lhui', 'value': 0xe4000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'lwi', 'value': 0xe8000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'sbi', 'value': 0xf0000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'shi', 'value': 0xf4000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
        {'name': 'swi', 'value': 0xf8000000, 'mask': 0xfc000000, 'feature': CF_USE1|CF_USE2|CF_USE3, 'flags': 0x50020101}, #
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 5

    assembler = {
        'flag' : ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
        'uflag' : 0,
        'name': "GNU assembler",
        'origin': ".org",
        'end': "end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': ".ascii",
        'a_byte': ".byte",
        'a_word': ".short",
        'a_dword': ".int",
        'a_qword': ".quad",
        'a_oword': ".int128",
        'a_float': ".float",
        'a_double': ".double",
        #'a_tbyte': "dt",
        #'a_dups': "#d dup(#v)",
        'a_bss': "dfs %s",
        'a_seg': "seg",
        'a_curip': ".",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': ".extrn",
        'a_comdef': "",
        'a_align': ".align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
    }

    FL_SIGNED = 1

    def notify_init(self, idp_file):
        # init returns >=0 on success
        ida_ida.cvar.inf.set_be(True)
        return 0

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #

    def handle_operand(self, insn, op, flag):
        flags     = get_flags(insn.ea)
        is_offs   = is_off(flags, op.n)
        isRead = True # !!!
        dref_flag = dr_R if isRead else dr_W
        def_arg   = is_defarg(flags, op.n)
        optype    = op.type

        if optype == o_imm:
            # create xrefs to valid addresses
            makeoff = False
            if op.n == 2 and self.instruc[insn.itype]["name"] in ["swi", "lwi"] and is_reg(insn.Op2, 0):
                makeoff = True
            if makeoff and not def_arg:
                op_plain_offset(insn.ea, op.n, insn.cs)
                is_offs = True
            if is_offs:
                insn.add_off_drefs(op, dr_O, 0)
        elif optype == o_displ:
            # create data xrefs and stack vars
            if is_offs:
                insn.add_off_drefs(op, dref_flag, OOF_ADDR)
        elif optype == o_mem:
            # create data xrefs
            insn.create_op_data(op.addr, op)
            insn.add_dref(op.addr, op.offb, dref_flag)
        elif optype == o_near:
            # create code xrefs
            if insn.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            has_delayslot = self.instruc[insn.itype]['name'].endswith('d')
            insn.add_cref(op.addr, op.offb, fl)

    # ----------------------------------------------------------------------
    def trace_sp(self, insn):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        pfn = get_func(insn.ea)
        if not pfn:
            return
        if is_reg(insn.Op1, 1) and self.instruc[insn.itype]['name'] == 'addik':
            if is_reg(insn.Op2, 1):
                print(insn.Op3.value)
                self.add_stkpnt(insn, pfn, fix_sign_32(insn.Op3.value))

    # ----------------------------------------------------------------------
    def add_stkpnt(self, insn, pfn, v):
        if pfn:
            end = insn.ea + insn.size
            if not is_fixed_spd(end):
                ida_frame.add_auto_stkpnt(pfn, end, v)

    def add_stkvar(self, insn, v, n, flag):
        pfn = get_func(insn.ea)
        if pfn and insn.create_stkvar(insn[n], fix_sign_32(v), flag):
            op_stkvar(insn.ea, n)

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        Feature = insn.get_canon_feature()

        if Feature & CF_USE1:
                self.handle_operand(insn, insn.Op1, 1)
        if Feature & CF_CHG1:
                self.handle_operand(insn, insn.Op1, 0)
        if Feature & CF_USE2:
                self.handle_operand(insn, insn.Op2, 1)
        if Feature & CF_CHG2:
                self.handle_operand(insn, insn.Op2, 0)
        if Feature & CF_USE3:
                self.handle_operand(insn, insn.Op3, 1)
        if Feature & CF_CHG3:
                self.handle_operand(insn, insn.Op3, 0)
        if Feature & CF_USE4:
                self.handle_operand(insn, insn.Op4, 1)
        if Feature & CF_CHG4:
                self.handle_operand(insn, insn.Op4, 0)
        if Feature & CF_JUMP:
                remember_problem(PR_JUMP, insn.ea)

        flow = (Feature & CF_STOP == 0)
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        if is_reg(insn.Op2, 1) and not is_reg(insn.Op1, 1) and insn.Op3.type == o_imm:
            self.add_stkvar(insn, insn.Op3.value, 3, 0)

        if may_trace_sp():
                if flow:
                        self.trace_sp(insn) # trace modification of SP register
                else:
                        recalc_spd(insn.ea) # recalculate SP register for the next insn

        return 1

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type
        fl = op.specval
        signed = OOF_SIGNED if fl & self.FL_SIGNED != 0 else 0
        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            ctx.out_value(op, OOFW_IMM | signed)
        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            ctx.out_value(op, OOF_ADDR | (OOFW_32 if self.PTRSZ == 4 else OOFW_64) | signed )
            ctx.out_symbol('(')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(')')
        return True

    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()

        ctx.out_one_operand(0)

        for i in range(1, 4):
                op = ctx.insn[i]
                if op.type == o_void:
                        break

                ctx.out_symbol(',')
                ctx.out_char(' ')
                ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    def decode_insn(self, insn, b, insnum, imm_high):
        ins = self.instruc[insnum]
        insn.itype = insnum
        OP1_IS_RD =  0x01
        OP1_IS_IMM = 0x02
        OP1_IS_SD =  0x04
        OP1_IS_RA =  0x08
        OP1_IS_RB =  0x10
        OP1_IS_IMM5F = 0x20

        OP2_IS_RA =  0x100
        OP2_IS_RB =  0x200
        OP2_IS_SA =  0x400
        OP2_IS_IMM14 = 0x800
        OP2_IS_IMM  = 0x1000

        OP3_IS_RB =  0x10000
        OP3_IS_IMM = 0x20000
        OP3_IS_IMM5 = 0x40000
        OP3_IS_IMMW = 0x80000

        OP4_IS_IMMS = 0x100000

        IMM_IS_SIGNED = 0x10000000
        IMM_IS_PC_RELATIVE = 0x20000000
        OP3_IS_DISPL = 0x40000000

        rd = (b >> 21) & 0x1F
        ra = (b >> 16) & 0x1F
        rb = (b >> 11) & 0x1F
        imm = (b & 0xFFFF)
        imm_dtype = dt_word
        if imm_high is not None:
            imm |= (imm_high << 16)
            imm_dtype = dt_dword
        imm5 = b & 0x3F
        imm14 = b & 0x3FFF
        imm5f = (b >> 21) & 0x3F


        flags = ins['flags']
        specval_imm = self.FL_SIGNED if (flags & IMM_IS_SIGNED) else 0
        imm_is_addr = (flags & IMM_IS_PC_RELATIVE)
        if imm_high is None and imm & 0x8000 and flags & IMM_IS_SIGNED:
             imm -= 0x10000
             imm = fix_sign_32(imm)

        if flags & IMM_IS_PC_RELATIVE:
             specval_imm = 0
             imm += insn.ea
             if imm_high is not None:
                 imm += 4 # skip IMM

        if flags & OP1_IS_RD:
             insn.Op1.type = o_reg
             insn.Op1.reg = rd
             insn.Op1.dtype = dt_word

        if flags & OP1_IS_IMM and not imm_is_addr:
             insn.Op1.type = o_imm
             insn.Op1.value = imm
             insn.Op1.dtype = imm_dtype
             insn.Op1.specval = specval_imm

        if flags & OP1_IS_IMM and imm_is_addr:
             insn.Op1.type = o_near
             insn.Op1.addr = imm
             insn.Op1.dtype = imm_dtype

        if flags & OP1_IS_SD:
             insn.Op1.type = o_reg
             insn.Op1.reg = self.reg_names.index(self.special_regs.get(imm14))
             insn.Op1.dtype = dt_word

        if flags & OP1_IS_RA:
             insn.Op1.type = o_reg
             insn.Op1.reg = ra
             insn.Op1.dtype = dt_word

        if flags & OP1_IS_RB:
             insn.Op1.type = o_reg
             insn.Op1.reg = rb
             insn.Op1.dtype = dt_word

        if flags & OP1_IS_IMM5F:
             insn.Op1.type = o_imm
             insn.Op1.value = imm5f
             insn.Op1.dtype = dt_word

        if flags & OP2_IS_RA:
             insn.Op2.type = o_reg
             insn.Op2.reg = ra
             insn.Op2.dtype = dt_word

        if flags & OP2_IS_RB:
             insn.Op2.type = o_reg
             insn.Op2.reg = rb
             insn.Op2.dtype = dt_word

        if flags & OP2_IS_SA:
             insn.Op2.type = o_reg
             insn.Op2.reg = self.reg_names.index(self.special_regs.get(imm14))
             insn.Op2.dtype = dt_word

        if flags & OP2_IS_IMM14:
             insn.Op2.type = o_imm
             insn.Op2.value = imm14
             insn.Op2.dtype = dt_word

        if flags & OP2_IS_IMM and not imm_is_addr:
             insn.Op2.type = o_imm
             insn.Op2.value = imm
             insn.Op2.dtype = imm_dtype
             insn.Op2.specval = specval_imm

        if flags & OP2_IS_IMM and imm_is_addr:
             insn.Op2.type = o_near
             insn.Op2.addr = imm
             insn.Op2.dtype = dt_word

        if flags & OP3_IS_RB:
             insn.Op3.type = o_reg
             insn.Op3.reg = rb
             insn.Op3.dtype = dt_word

        if flags & OP3_IS_IMM and not imm_is_addr:
#             if flags & OP3_IS_DISPL:
             insn.Op3.type = o_imm
#             else:
#                 insn.Op3.type = o_disp

             insn.Op3.value = imm
             insn.Op3.dtype = imm_dtype
             insn.Op3.specval = specval_imm

        if flags & OP3_IS_IMM and imm_is_addr:
             insn.Op3.type = o_near
             insn.Op3.addr = imm
             insn.Op3.dtype = dt_word

        if flags & OP3_IS_IMM5:
             insn.Op3.type = o_imm
             insn.Op3.value = imm5
             insn.Op3.dtype = dt_word

        if flags & OP3_IS_IMMW:
             insn.Op3.type = o_imm
             insn.Op3.value = immw
             insn.Op3.dtype = dt_word

        if flags & OP4_IS_IMMS:
             insn.Op.type = o_imm
             insn.Op4.value = imms
             insn.Op4.dtype = dt_word

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        b = insn.get_next_dword()
        imm_high = None
        if (b & 0xFFFF0000) == 0xB0000000: # Imm instruction
            imm_high = b & 0xFFFF
            b = insn.get_next_dword()
        insn_found = 0
        for insnum, ins in enumerate(self.instruc):
            if b & ins['mask'] == ins['value']:
                self.decode_insn(insn, b, insnum, imm_high)
                return insn.size


        print("unknown insn %08x" % b)

        return 0

    def __init__(self):
        print("HELO WORLD INIT")
        idaapi.processor_t.__init__(self)

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return microblaze_processor_t()
