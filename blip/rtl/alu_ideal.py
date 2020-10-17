import blip
import blip.isa as isa
import blip.rtl as rtl
import itertools
from nmigen import *
from nmigen.build import Platform
from nmigen.back.pysim import Simulator, Delay

class AluIdeal(rtl.AluInterface):
    def __init__(self):
        super().__init__()

    def elaborate(self, platform: Platform) -> Module:
        m = Module()
        with m.Switch(self.op):
            with m.Case(isa.AluOp.SUB):
                m.d.comb += self.out.eq(self.a - self.b)
            with m.Case(isa.AluOp.AND):
                m.d.comb += self.out.eq(self.a & self.b)
            with m.Case(isa.AluOp.OR):
                m.d.comb += self.out.eq(self.a | self.b)
            with m.Case(isa.AluOp.XOR):
                m.d.comb += self.out.eq(self.a ^ self.b)
            with m.Case(isa.AluOp.SHL):
                m.d.comb += self.out.eq(self.a << self.b)
            with m.Case(isa.AluOp.SHR):
                m.d.comb += self.out.eq(self.a >> self.b)
            with m.Case(isa.AluOp.SAR):
                m.d.comb += self.out.eq(self.a.as_signed() >> self.b)
            with m.Case(isa.AluOp.MUL):
                m.d.comb += self.out.eq(self.a * self.b)
            with m.Case(isa.AluOp.ADD):
                m.d.comb += self.out.eq(self.a + self.b)
        return m

@blip.check
def check_fixtures():
    m = Module()
    m.submodules.alu = alu = AluIdeal()
    sim = Simulator(m)

    fixtures = set([0, 1, 2, 100, 0xaaaa_aaaa, 0x00001000, 0x8000_0000, 0xffff_fffe, 0xffff_ffff])
    fixtures = list(sorted(fixtures))
    num_checks = 0

    def process():
        nonlocal num_checks
        for op in isa.AluOp:
            yield alu.op.eq(op)
            for a in fixtures:
                yield alu.a.eq(a)
                for b in fixtures:
                    yield alu.b.eq(b)
                    yield Delay(1e-9)
                    ref_out, ref_flags = isa.emu.eval_alu(op, a, b)
                    out = yield alu.out
                    assert out == ref_out
                    num_checks += 1

    sim.add_process(process)
    sim.run()

    blip.info(f"Checked {num_checks} inputs")

