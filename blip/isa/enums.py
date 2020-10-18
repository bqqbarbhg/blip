from enum import IntEnum, IntFlag

class Reg(IntEnum):
    A  = 0x0
    B  = 0x1
    C  = 0x2
    D  = 0x3
    X  = 0x4
    Y  = 0x5
    Z  = 0x6
    W  = 0x7
    P  = 0x8
    Q  = 0x9
    R  = 0xa
    S  = 0xb
    T  = 0xc
    U  = 0xd
    SP = 0xe
    LR = 0xf

class AluOp(IntEnum):
    SUB = 0x0
    AND = 0x1
    OR  = 0x2
    XOR = 0x3
    SHL = 0x4
    SHR = 0x5
    SAR = 0x6
    MUL = 0x7
    MULS = 0x8
    DIV = 0x9
    ADD = 0x10

class Cond(IntEnum):
    T = 0x0
    Z = 0x1
    C = 0x2
    O = 0x3
    S = 0x4
    A = 0x5
    L = 0x6
    G = 0x7

class Flags(IntFlag):
    C = 0x1
    Z = 0x2
    O = 0x4
    S = 0x8