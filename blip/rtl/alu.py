from nmigen import *
from nmigen.build import Platform
import blip.isa as isa

class AluInterface(Elaboratable):
    def __init__(self):
        self.op = Signal(isa.AluOp)
        self.a = Signal(32)
        self.b = Signal(32)
        self.out = Signal(32)
        self.busy = Signal()
        self.flags = Signal(isa.Flags)

