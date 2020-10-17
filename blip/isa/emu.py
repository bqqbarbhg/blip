import blip
from blip.isa import Reg, AluOp, Cond, Flags
from functools import cache

def emu_inst(name):
    def decorator(func):
        return func

class BadInstructionError(RuntimeError):
    def __init__(self):
        super().__init__("Bad instruction")

class Emulator:
    def __init__(self, memory, pc=0):
        self.memory = memory
        self.imm = 0
        self.imm_bits = 0
        self.pc = pc
        self.regs = [0] * 16
        self.flags = Flags(0)
        self.emu_map = init_emu_insts()
        self.stop = False

    def get_imm(self, v: int, bits: int = 4) -> int:
        imm = self.imm << 4 | v
        return blip.to_signed(imm, max(bits, self.imm_bits + 4)) & 0xffff_ffff

    def load(self, ptr: int, size: int) -> int:
        mem = self.memory
        if size == 1:
            return mem[ptr]
        elif size == 2:
            assert ptr % 2 == 0
            a, b = mem[ptr], mem[ptr + 1]
            return a | b << 8
        else:
            assert ptr % 4 == 0
            a, b, c, d = mem[ptr], mem[ptr + 1], mem[ptr + 2], mem[ptr + 3]
            return a | b << 8 | c << 16 | d << 24

    def store(self, ptr: int, val: int, size: int) -> int:
        mem = self.memory
        if size == 1:
            mem[ptr] = val
        elif size == 2:
            assert ptr % 2 == 0
            mem[ptr], mem[ptr + 1] = val, val >> 8
        else:
            assert ptr % 4 == 0
            mem[ptr], mem[ptr + 1], mem[ptr + 2], mem[ptr + 3] = val, val >> 8, val >> 16, val >> 24

    def do_sys(self, sys):
        if sys == 0x1:
            self.stop = True

    def step(self):
        bits = self.load(self.pc, 2)
        self.pc += 2

        for bit_mask, inst_map in self.emu_map:
            pair = inst_map.get(bits & bit_mask)
            if pair: break
        else:
            raise BadInstructionError()

        inst, imp = pair
        imp(self, bits)

        if (bits & 0xc000) != 0x4000:
            self.imm = 0
            self.imm_bits = 0

CF = int(Flags.C)
ZF = int(Flags.Z)
SF = int(Flags.S)
OF = int(Flags.O)

def eval_alu(op: AluOp, a: int, b: int) -> (int, Flags):
    word = 0xffff_ffff
    assert a <= word
    assert b <= word
    r = 0
    if op == AluOp.SUB:   r = (a - b)
    elif op == AluOp.AND: r = a & b
    elif op == AluOp.OR:  r = a | b
    elif op == AluOp.XOR: r = a ^ b
    elif op == AluOp.SHL: r = (a << min(b, 32))
    elif op == AluOp.SHR: r = (a >> min(b, 32))
    elif op == AluOp.SAR: r = ((word << 32 | a) >> min(b, 32))
    elif op == AluOp.MUL: r = a * b
    elif op == AluOp.ADD: r = a + b
    f = 0

    if (r & word) == 0: f |= ZF
    if op == AluOp.ADD or op == AluOp.SUB:
        if r >= 0x1_0000_0000: flags |= CF
        if ((~(a^b)) & (a^r)) & 0x8000_0000: OF
        if r & 0x8000_0000: flags |= SF

    return (r & word), Flags(f)

def eval_cond(cond: Cond, flags: Flags) -> bool:
    f = int(flags)
    if cond == Cond.T:   ok = True
    elif cond == Cond.Z: ok = (f & ZF) != 0
    elif cond == Cond.C: ok = (f & CF) != 0
    elif cond == Cond.O: ok = (f & OF) != 0
    elif cond == Cond.F: ok = (f & SF) != 0
    elif cond == Cond.A: ok = (f & (SF|ZF)) == 0
    elif cond == Cond.L: ok = ((f & SF) != 0) != ((f & OF) != 0)
    elif cond == Cond.G: ok = ((f & ZF) == 0) and ((f & SF) != 0) == ((f & OF) != 0)
    return ok

@cache
def init_emu_insts():
    emu_map = { }
    inst_map = blip.isa.assembler.init_assembler_insts()

    def emu_exec0(inst, fn):
        def emu_exec0_imp(emu, bits):
            fn(emu)
        return emu_exec0_imp

    def emu_exec1(inst, fn):
        shift0, mask0 = inst.args[0].offset, (1 << inst.args[0].bits) - 1
        def emu_exec1_imp(emu, bits):
            arg0 = bits >> shift0 & mask0
            fn(emu, arg0)
        return emu_exec1_imp

    def emu_exec2(inst, fn):
        shift0, mask0 = inst.args[0].offset, (1 << inst.args[0].bits) - 1
        shift1, mask1 = inst.args[1].offset, (1 << inst.args[1].bits) - 1
        def emu_exec2_imp(emu, bits):
            arg0 = bits >> shift0 & mask0
            arg1 = bits >> shift1 & mask1
            fn(emu, arg0, arg1)
        return emu_exec2_imp

    def emu_exec3(inst, fn):
        shift0, mask0 = inst.args[0].offset, (1 << inst.args[0].bits) - 1
        shift1, mask1 = inst.args[1].offset, (1 << inst.args[1].bits) - 1
        shift2, mask2 = inst.args[2].offset, (1 << inst.args[2].bits) - 1
        def emu_exec3_imp(emu, bits):
            arg0 = bits >> shift0 & mask0
            arg1 = bits >> shift1 & mask1
            arg2 = bits >> shift2 & mask2
            fn(emu, arg0, arg1, arg2)
        return emu_exec3_imp
    
    emu_exec_nary = [
        emu_exec0, emu_exec1, emu_exec2, emu_exec3
    ]

    def inst(name, fmt, func):
        inst = inst_map[(name, fmt)]
        format_map = emu_map.setdefault(inst.bit_mask, {})
        assert inst.bit_set not in format_map
        imp = emu_exec_nary[len(fmt)](inst, func)
        format_map[inst.bit_set] = (inst, imp)

    def emu_imm_v(emu, v):
        emu.imm = (emu.imm << 14) | v
        emu.imm_bits += 14

    def emu_ld(emu, d, r, v):
        imm = emu.get_imm(v)
        emu.regs[d] = emu.load((emu.regs[r] + imm*4) & 0xffff_ffff, 4)

    def emu_st(emu, d, r, v):
        imm = emu.get_imm(v)
        emu.load((emu.regs[r] + imm*4) & 0xffff_ffff, emu.regs[d], 4)

    def emu_ldb(emu, d, r):
        emu.regs[d] = emu.load(emu.regs[r], 1)

    def emu_stb(emu, d, r):
        emu.load(emu.regs[r], emu.regs[d], 1)

    def emu_ldh(emu, d, r):
        emu.regs[d] = emu.load(emu.regs[r], 2)

    def emu_sth(emu, d, r):
        emu.load(emu.regs[r], emu.regs[d], 2)

    def emu_alu(emu, op, d, r, s):
        emu.regs[d], emu.flags = eval_alu(op, emu.regs[r], emu.regs[s])

    def emu_alui(emu, op, d, r, v):
        emu.regs[d], emu.flags = eval_alu(op, emu.regs[r], emu.get_imm(v))

    def emu_cmp(emu, op, r, s):
        _, emu.flags = eval_alu(op, emu.regs[r], emu.regs[s])

    def emu_cmpi(emu, op, r, v):
        _, emu.flags = eval_alu(op, emu.regs[r], emu.get_imm(v))

    def emu_bcc(emu, ref, cond, v):
        if eval_cond(cond, emu.flags) == ref:
            emu.pc = (emu.pc + emu.get_imm(v, 8)*2) & 0xffff_ffff

    def emu_mov(emu, d, v):
        emu.regs[d] = emu.get_imm(v, 4)

    def emu_apc(emu, d, v):
        emu.regs[d] = (emu.pc + emu.get_imm(v)) & 0xffff_ffff

    def emu_bsr(emu, r):
        reg = emu.regs[r]
        emu.regs[Reg.LR] = emu.pc
        emu.pc = reg

    def emu_bsri(emu, v):
        emu.regs[Reg.LR] = emu.pc
        emu.pc = (emu.pc + emu.get_imm(v)) & 0xffff_ffff

    def emu_bra(emu, r):
        emu.pc = emu.regs[r]

    def emu_brai(emu, v):
        emu.pc = emu.get_imm(v)

    def emu_sys(emu, r):
        emu.do_sys(emu.regs[r])

    def emu_sysi(emu, v):
        emu.do_sys(emu.get_imm(v))

    def emu_nop(emu, v):
        pass

    inst("imm", "v", emu_imm_v)
    inst("ld", "rrv", emu_ld)
    inst("st", "rrv", emu_st)
    inst("add", "rrr", lambda emu,d,r,s: emu_alu(emu, AluOp.ADD, d, r, s))
    inst("add", "rrv", lambda emu,d,r,v: emu_alui(emu, AluOp.ADD, d, r, v))
    inst("sub", "rr", lambda emu,d,s: emu_alu(emu, AluOp.SUB, d, d, s))
    inst("sub", "rv", lambda emu,d,v: emu_alui(emu, AluOp.SUB, d, d, v))
    inst("and", "rr", lambda emu,d,s: emu_alu(emu, AluOp.AND, d, d, s))
    inst("and", "rv", lambda emu,d,v: emu_alui(emu, AluOp.AND, d, d, v))
    inst("or", "rr", lambda emu,d,s: emu_alu(emu, AluOp.OR, d, d, s))
    inst("or", "rv", lambda emu,d,v: emu_alui(emu, AluOp.OR, d, d, v))
    inst("xor", "rr", lambda emu,d,s: emu_alu(emu, AluOp.XOR, d, d, s))
    inst("xor", "rv", lambda emu,d,v: emu_alui(emu, AluOp.XOR, d, d, v))
    inst("shl", "rr", lambda emu,d,s: emu_alu(emu, AluOp.SHL, d, d, s))
    inst("shl", "rv", lambda emu,d,v: emu_alui(emu, AluOp.SHL, d, d, v))
    inst("shr", "rr", lambda emu,d,s: emu_alu(emu, AluOp.SHR, d, d, s))
    inst("shr", "rv", lambda emu,d,v: emu_alui(emu, AluOp.SHR, d, d, v))
    inst("sar", "rr", lambda emu,d,s: emu_alu(emu, AluOp.SAR, d, d, s))
    inst("sar", "rv", lambda emu,d,v: emu_alui(emu, AluOp.SAR, d, d, v))
    inst("mul", "rr", lambda emu,d,s: emu_alu(emu, AluOp.MUL, d, d, s))
    inst("mul", "rv", lambda emu,d,v: emu_alui(emu, AluOp.MUL, d, d, v))
    inst("bnt", "v", lambda emu,v: emu_bcc(emu, False, Cond.T, v))
    inst("bt", "v", lambda emu,v: emu_bcc(emu, True, Cond.T, v))
    inst("bnz", "v", lambda emu,v: emu_bcc(emu, False, Cond.Z, v))
    inst("bz", "v", lambda emu,v: emu_bcc(emu, True, Cond.Z, v))
    inst("bnc", "v", lambda emu,v: emu_bcc(emu, False, Cond.C, v))
    inst("bc", "v", lambda emu,v: emu_bcc(emu, True, Cond.C, v))
    inst("bno", "v", lambda emu,v: emu_bcc(emu, False, Cond.O, v))
    inst("bo", "v", lambda emu,v: emu_bcc(emu, True, Cond.O, v))
    inst("bns", "v", lambda emu,v: emu_bcc(emu, False, Cond.S, v))
    inst("bs", "v", lambda emu,v: emu_bcc(emu, True, Cond.S, v))
    inst("bna", "v", lambda emu,v: emu_bcc(emu, False, Cond.A, v))
    inst("ba", "v", lambda emu,v: emu_bcc(emu, True, Cond.A, v))
    inst("bnl", "v", lambda emu,v: emu_bcc(emu, False, Cond.L, v))
    inst("bl", "v", lambda emu,v: emu_bcc(emu, True, Cond.L, v))
    inst("bng", "v", lambda emu,v: emu_bcc(emu, False, Cond.G, v))
    inst("bg", "v", lambda emu,v: emu_bcc(emu, True, Cond.G, v))
    inst("cmp", "rr", lambda emu,r,s: emu_cmp(emu, AluOp.SUB, r, s))
    inst("cmp", "rv", lambda emu,r,v: emu_cmpi(emu, AluOp.SUB, r, v))
    inst("tst", "rr", lambda emu,r,s: emu_cmp(emu, AluOp.AND, r, s))
    inst("tst", "rv", lambda emu,r,v: emu_cmpi(emu, AluOp.AND, r, v))
    inst("ldb", "rr", emu_ldb)
    inst("stb", "rr", emu_stb)
    inst("ldh", "rr", emu_ldh)
    inst("sth", "rr", emu_sth)
    inst("mov", "rv", emu_mov)
    inst("apc", "rv", emu_apc)
    inst("bsr", "r", emu_bsr)
    inst("bsr", "v", emu_bsri)
    inst("bra", "r", emu_bra)
    inst("bra", "v", emu_brai)
    inst("sys", "r", emu_sys)
    inst("sys", "v", emu_sysi)
    inst("nop", "", emu_nop)

    return list(emu_map.items())

def assemble_and_run(source, max_steps=0x10000, ram_size=0x10000):
    obj = blip.isa.assemble(source)
    binary = blip.isa.link([obj])
    memory = binary.data + bytes(ram_size)
    pc = 0
    for sym in binary.symbols:
        if sym == "main":
            pc = sym.offset
            break
    emu = Emulator(memory, pc)
    for n in range(max_steps):
        emu.step()
        if emu.stop: break
    else:
        raise RuntimeError("Program did not halt")
    return emu


@blip.check
def check_simple():
    src = """
        mov X, 1
        mov Y, 2
        add Z, X, Y
        sys 1
    """
    emu = assemble_and_run(src)
    assert emu.regs[Reg.X] == 1
    assert emu.regs[Reg.Y] == 2
    assert emu.regs[Reg.Z] == 3

@blip.check
def check_strlen():
    src = """
        apc X, message
        bsr strlen
        sys 1
    strlen:
        mov Y, X
        sub X, 1
    _loop:
        add X, 1
        ldb Z, X
        tst Z, -1
        bnz _loop
        sub X, Y
        ret
    message:
        .asciz "Hello World!"
    """
    emu = assemble_and_run(src)
    assert emu.regs[Reg.X] == 12
