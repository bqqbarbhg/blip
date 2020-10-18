import blip
from dataclasses import dataclass

@dataclass
class InstArg:
    name: str
    offset: int
    bits: int
    format: str

class Inst:
    def __init__(self, encoding, mnemonic, **kwargs):
        name, *args = mnemonic.split(" ")
        enc = encoding.replace(" ", "")

        arg_range = { }
        bit_mask = 0
        bit_set = 0
        for i,c in enumerate(enc):
            bit = 15 - i
            if c == "0":
                bit_mask |= 1 << bit
            elif c == "1":
                bit_mask |= 1 << bit
                bit_set |= 1 << bit
            else:
                r = arg_range.get(c, (bit + 1, bit + 1))
                assert r[0] == bit + 1, "Argument bits must be consecutive"
                arg_range[c] = (bit, r[1])
        for arg in args:
            assert arg in arg_range, f"Argument without encoding: {arg}"
        for arg in arg_range.keys():
            assert arg in args, f"Encoding without argument: {arg}"

        imm_bits = 0
        fmt = ""
        inst_args = []
        for arg in args:
            r = arg_range[arg]
            if arg == "v":
                f = "v"
                imm_bits = r[1] - r[0]
            else:
                f = "r"
            inst_args.append(InstArg(arg, r[0], r[1] - r[0], f))
            fmt += f

        self.name = name
        self.imm_scale = kwargs.get("imm_scale", 1)
        self.imm_relative = kwargs.get("imm_relative", True)
        self.imm_bits = imm_bits
        self.bit_mask = bit_mask
        self.bit_set = bit_set
        self.args = inst_args
        self.format = fmt

    def name_with_args(self) -> str:
        if self.args:
            args = ", ".join(a.name for a in self.args)
            return f"{self.name} {args}"
        else:
            return self.name

insts = [
    Inst("01vv vvvv vvvv vvvv", "imm v", prefix=True),
    Inst("1000 dddd rrrr vvvv", "ld d r v", imm_scale=4),
    Inst("1001 dddd rrrr vvvv", "st d r v", imm_scale=4),
    Inst("1010 dddd rrrr ssss", "add d r s"),
    Inst("1011 dddd rrrr vvvv", "add d r v"),
    Inst("1100 0000 dddd ssss", "sub d s"),
    Inst("1100 0001 dddd ssss", "and d s"),
    Inst("1100 0010 dddd ssss", "or d s"),
    Inst("1100 0011 dddd ssss", "xor d s"),
    Inst("1100 0100 dddd ssss", "shl d s"),
    Inst("1100 0101 dddd ssss", "shr d s"),
    Inst("1100 0110 dddd ssss", "sar d s"),
    Inst("1100 0111 dddd ssss", "mul d s"),
    Inst("1100 1000 dddd ssss", "muls d s"),
    Inst("1100 1001 dddd ssss", "div d s"),
    Inst("1101 0000 dddd vvvv", "sub d v"),
    Inst("1101 0001 dddd vvvv", "and d v"),
    Inst("1101 0010 dddd vvvv", "or d v"),
    Inst("1101 0011 dddd vvvv", "xor d v"),
    Inst("1101 0100 dddd vvvv", "shl d v"),
    Inst("1101 0101 dddd vvvv", "shr d v"),
    Inst("1101 0110 dddd vvvv", "sar d v"),
    Inst("1101 0111 dddd vvvv", "mul d v"),
    Inst("1101 1000 dddd vvvv", "muls d v"),
    Inst("1101 1001 dddd vvvv", "div d v"),
    Inst("1110 0000 vvvv vvvv", "bnt v", imm_scale=2, imm_relative=True),
    Inst("1110 0001 vvvv vvvv", "bt v",  imm_scale=2, imm_relative=True),
    Inst("1110 0010 vvvv vvvv", "bnz v", imm_scale=2, imm_relative=True),
    Inst("1110 0011 vvvv vvvv", "bz v",  imm_scale=2, imm_relative=True),
    Inst("1110 0100 vvvv vvvv", "bnc v", imm_scale=2, imm_relative=True),
    Inst("1110 0101 vvvv vvvv", "bc v",  imm_scale=2, imm_relative=True),
    Inst("1110 0110 vvvv vvvv", "bno v", imm_scale=2, imm_relative=True),
    Inst("1110 0111 vvvv vvvv", "bo v",  imm_scale=2, imm_relative=True),
    Inst("1110 1000 vvvv vvvv", "bns v", imm_scale=2, imm_relative=True),
    Inst("1110 1001 vvvv vvvv", "bs v",  imm_scale=2, imm_relative=True),
    Inst("1110 1010 vvvv vvvv", "bna v", imm_scale=2, imm_relative=True),
    Inst("1110 1011 vvvv vvvv", "ba v",  imm_scale=2, imm_relative=True),
    Inst("1110 1100 vvvv vvvv", "bnl v", imm_scale=2, imm_relative=True),
    Inst("1110 1101 vvvv vvvv", "bl v",  imm_scale=2, imm_relative=True),
    Inst("1110 1110 vvvv vvvv", "bng v", imm_scale=2, imm_relative=True),
    Inst("1110 1111 vvvv vvvv", "bg v",  imm_scale=2, imm_relative=True),
    Inst("1111 0000 rrrr ssss", "cmp r s"),
    Inst("1111 0001 rrrr vvvv", "cmp r v"),
    Inst("1111 0010 rrrr ssss", "tst r s"),
    Inst("1111 0011 rrrr vvvv", "tst r v"),
    Inst("1111 0100 dddd ssss", "ldb d s"),
    Inst("1111 0101 dddd ssss", "stb d s"),
    Inst("1111 0110 dddd ssss", "ldh d s"),
    Inst("1111 0111 dddd ssss", "sth d s"),
    Inst("1111 1000 dddd vvvv", "mov d v"),
    Inst("1111 1001 dddd vvvv", "apc d v", imm_relative=True),
    Inst("1111 1010 dddd 0000", "ext d"),
    # Inst("1111 1001 dddd 0001", "clz d v"), # maybe
    # Inst("1111 1001 dddd 0010", "ctz d v"), # maybe
    Inst("1111 1111 0000 rrrr", "bsr r"),
    Inst("1111 1111 0001 vvvv", "bsr v", imm_relative=True),
    Inst("1111 1111 0010 rrrr", "bra r"),
    Inst("1111 1111 0011 vvvv", "bra v"),
    Inst("1111 1111 0100 rrrr", "sys r"),
    Inst("1111 1111 0101 vvvv", "sys v"),
    Inst("1111 1111 1111 0000", "nop"),
]

@blip.check
def check_insts():
    import string
    namechars = set(string.ascii_lowercase)
    for inst in insts:
        assert all(c in namechars for c in inst.name)
        assert inst.imm_relative in (False, True)
        assert inst.imm_scale in (1, 2, 4)
        assert (inst.bit_set & inst.bit_mask) == inst.bit_set
    blip.info(f"{len(insts)} instructions defined")

@blip.check
def check_encoding_space():
    inst_map = { }
    for n, inst in enumerate(insts):
        free_bits = (~inst.bit_mask) & 0xffff
        for arg_bits in range(0x10000):
            if (arg_bits & free_bits) != arg_bits: continue
            bits = inst.bit_set | arg_bits
            if bits in inst_map:
                other = insts[inst_map[bits]]
                msg = f"Encoding collision at {bits:16b}: '{inst.name_with_args()}' vs '{other.name_with_args()}'"
                raise ValueError(msg)
            inst_map[bits] = n
    blip.info(f"Encoding space used: {len(inst_map) / 0x10000*100:.1f}%")

@blip.check
def check_mnemonic_space():
    inst_map = { }
    for n, inst in enumerate(insts):
        pair = (inst.name, inst.format)
        if pair in inst_map:
            msg = f"Mnemonic collision: {inst.name} ({inst.format})"
            raise ValueError(msg)
        inst_map[pair] = n
