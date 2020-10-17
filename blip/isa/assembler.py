from collections import namedtuple
from dataclasses import dataclass
from functools import cache
from typing import Sequence
import dataclasses
import blip
import json
import binascii

@dataclass
class Symbol:
    name: str
    offset: int

@dataclass
class Reloc:
    name: str
    offset: int
    imm_bits: int
    imm_scale: int
    imm_relative: int

    # TODO: More relocation types
    def begin(self):
        return self.offset - 4
    def end(self):
        return self.offset + 2

@dataclass
class Section:
    name: str
    align: int
    data: bytes
    symbols: list[Symbol]
    relocs: list[Reloc]

@dataclass
class ObjectFile:
    sections: list[Section]

class AssembleError(RuntimeError):
    def __init__(self, msg):
        super().__init__(msg)

Label = namedtuple("Label", "name piece_ix offset lineno")

def fail(message):
    raise AssembleError(message)

class Piece:
    def __init__(self, data, section, label, imm_relative, imm_scale, imm_bits, align=2, skip_size=0):
        self.data = data
        self.section = section
        self.label = label
        self.imm_relative = imm_relative
        self.imm_scale = imm_scale
        self.imm_bits = imm_bits
        self.offset = 0
        if imm_bits:
            self.prefix_size = 4
        else:
            self.prefix_size = 0
        self.skip_size = skip_size
        self.align_padding = 0
        self.align = align
        self.found_label = None

def find_first(s, chars):
    return min(s.find(c) if c in s else len(s) for c in chars)

@cache
def init_assembler_insts():
    inst_map = { }
    for inst in blip.isa.insts:
        inst_map[(inst.name, inst.format)] = inst
    return inst_map

@cache
def init_assembler_macros():
    macro_map = { }

    def add_macro(name, fmt, fn):
        if callable(fn):
            real_fn = fn
        elif isinstance(fn, str):
            def macro_str_fn(op, args):
                return fn.format(*args, op=op).split(";")
            real_fn = macro_str_fn
        else:
            raise TypeError("Invalid macro function type")

        macro_map.setdefault((name, fmt), []).append(real_fn)

    def macro_ldstbh(op, args):
        return [
            "add U, {1}, {2}".format(*args, op=op),
            "ldb {0}, U".format(*args, op=op),
        ]

    def macro_alu(op, args):
        if args[0] == args[1]:
            return ["{op} {0}, {2}".format(*args, op=op)]
        elif args[0] == "U":
            return ["{op}u {1}, {2}".format(*args, op=op)]
        else:
            return [
                "{op}u {1}, {2}".format(*args, op=op),
                "mov {0}, U".format(*args, op=op),
            ]

    add_macro("mov", "rr", "add {0}, {1}, 0")
    add_macro("add", "rr", "add {0}, {0}, {1}")
    add_macro("add", "rv", "add {0}, {0}, {1}")

    add_macro("ld", "rr", "ld {0}, {1}, 0")
    add_macro("st", "rr", "st {0}, {1}, 0")

    add_macro("ldb", "rrv", macro_ldstbh)
    add_macro("stb", "rrv", macro_ldstbh)
    add_macro("ldh", "rrv", macro_ldstbh)
    add_macro("sth", "rrv", macro_ldstbh)

    add_macro("ret", "", "bra LR")

    for op in blip.isa.AluOp:
        add_macro(str(op).lower(), "rrr", macro_alu)
        add_macro(str(op).lower(), "rrv", macro_alu)

    return macro_map

class Assembler:
    def __init__(self):
        self.pieces = []
        self.piece = Piece(bytearray(), "code", "", 0, 0, 0)
        self.section = "code"
        self.labels = { }
        self.fn = ""
        self.inst_map = init_assembler_insts()
        self.macro_map = init_assembler_macros()

    def process_line(self, line, lineno):

        # Strip comments and skip empty lines
        line = line[:find_first(line, ";#")].strip()
        if not line: return

        # Align to two bytes
        while len(self.piece.data) % 2 != 0:
            self.piece.data.append(0)

        # Process labels
        if line[-1] == ":":
            line = line[:-1]
            if line == "": fail("Empty label")
            if line[0] == "_":
                label = self.fn + "_" + line
            else:
                label = line
                self.fn = label
            if label in self.labels:
                fail("Label alredy defined at line {}: {}".format(self.labels[label].lineno, label))
            self.labels[label] = Label(label, len(self.pieces), len(self.piece.data), lineno)
            return

        # Process directives
        if line[0] == ".":
            line = line[1:].strip()
            if line == "": fail("Empty directive")
            parts = [p.strip() for p in line.split(" ", 1) if p.strip()]
            name = parts[0]

            if name == "ascii" or name == "asciz":
                try:
                    st = json.loads(parts[1])
                    if not isinstance(st, str):
                        raise TypeError()
                except:
                    fail("Bad string literal: {}".format(parts[1]))
                stb = st.encode("utf-8")
                self.piece.data += stb
                if name == "asciz":
                    self.piece.data.append(0)
            elif name == "align":
                align = int(parts[1], 0)
                self.flush()
                self.piece.align = max(self.piece.align, align)
            elif name == "section":
                self.section = parts[1]
                self.flush()
            else:
                fail("Unknown directive: {}".format(name))

            return

        # Split line to mnemonic name and arguments
        parts = [p.strip() for p in line.split(" ", 1) if p.strip()]
        name = parts[0]
        if len(parts) >= 2:
            args = [s.strip() for s in parts[1].split(",") if s.strip()]
        else:
            args = []

        # Get format from arguments
        fmt = ""
        label = ""
        for arg in args:
            if arg in blip.isa.Reg.__dict__:
                fmt += "r"
            else:
                fmt += "v"
                if arg[0] not in "+-0123456789":
                    label = arg
                    if label[0] == "_":
                        label = self.fn + "_" + label

        # Apply macro rules
        for macro in self.macro_map.get((name, fmt), []):
            result = macro(name, args)
            if result is not None:
                for subline in  result:
                    self.process_line(subline, lineno)
                return

        # Find matching instruction
        inst = self.inst_map.get((name, fmt))
        if not inst:
            fail("Unknown instruction: {} ({})".format(name, fmt))

        # Flush current piece if necessary
        if label:
            self.pieces.append(self.piece)
            self.piece = Piece(bytearray(), self.section, label, inst.imm_relative, inst.imm_scale, inst.imm_bits)

        # Encode the instruction
        inst_bits = inst.bit_set
        for arg, iarg in zip(args, inst.args):
            if iarg.format == "r":
                inst_bits |= blip.isa.Reg[arg] << iarg.offset
            elif iarg.format == "v":
                if label:
                    arg_bits = 0
                else:
                    try:
                        arg_bits = int(arg, 0)
                    except ValueError:
                        fail("Invalid immediate integer: {}".format(arg))

                    if arg_bits % inst.imm_scale != 0:
                        fail("Immediate for {} must be aligned to {}".format(inst.name, inst.imm_scale))
                    arg_bits //= inst.imm_scale

                    if not (-2**17 <= arg_bits <= 2**17):
                        word = (arg_bits >> 18 & 0x3fff) | 0x4000
                        self.piece.data.append(word & 0xff)
                        self.piece.data.append(word >> 8 & 0xff)
                    if not (-2**(inst.imm_bits-1) <= arg_bits <= 2**(inst.imm_bits-1) - 1):
                        word = (arg_bits >> 4 & 0x3fff) | 0x4000
                        self.piece.data.append(word & 0xff)
                        self.piece.data.append(word >> 8 & 0xff)
                    inst_bits |= arg_bits&(2**inst.imm_bits - 1) << iarg.offset

        self.piece.data.append(inst_bits & 0xff)
        self.piece.data.append(inst_bits >> 8 & 0xff)

    def flush(self):
        self.pieces.append(self.piece)
        self.piece = Piece(bytearray(), self.section, "", 0, 0, 0)

class Linker:
    def __init__(self, pieces, labels, section):
        self.pieces = pieces
        self.section = section
        self.labels = labels
        self.section_pieces = [p for p in pieces if p.section == section]

    def init_pieces(self):
        for piece in self.section_pieces:
            if not piece.label: continue
            label = self.labels.get(piece.label)
            if not label: continue
            if self.pieces[label.piece_ix].section == self.section:
                piece.found_label = label

    def layout_pieces(self):
        offset = 0
        for piece in self.section_pieces:
            padding = 0
            while offset % piece.align != 0:
                offset += 1
                padding += 1
            offset += piece.prefix_size - piece.skip_size
            piece.offset = offset
            piece.align_padding = padding
            offset += len(piece.data)

    def get_piece_imm(self, piece):
        if not piece.found_label: return 0
        label_piece = self.pieces[piece.found_label.piece_ix]
        value = label_piece.offset + piece.found_label.offset
        if piece.found_label.offset == 0:
            value -= label_piece.prefix_size - label_piece.skip_size
        if piece.imm_relative:
            value -= piece.offset + 2 + piece.skip_size
        if value % piece.imm_scale != 0:
            fail("Label {} must be aligned to {}".format(piece.label, piece.imm_scale))
        value //= piece.imm_scale
        return value

    def optimize_pieces(self):
        for piece in self.section_pieces:
            if not piece.imm_bits: continue
            if not piece.found_label: continue
            arg_bits = self.get_piece_imm(piece)
            prefix_words = 0
            if not (-2**17 <= arg_bits <= 2**17):
                prefix_words += 1
            if not (-2**(piece.imm_bits-1) <= arg_bits <= 2**(piece.imm_bits-1) - 1):
                prefix_words += 1
            piece.prefix_size = prefix_words * 2

    def layout(self, opt_n=3):
        self.init_pieces()
        self.layout_pieces()
        for n in range(opt_n):
            self.optimize_pieces()
            self.layout_pieces()

    def get_alignment(self):
        return max(p.align for p in self.pieces)

    def get_data(self):
        data = bytearray()
        for piece in self.section_pieces:
            pad = piece.align_padding
            if pad % 2 != 0:
                data.append(0)
            pad_nops = pad // 2
            while pad_nops:
                num_nops = min(pad_nops, len(nop_codes))
                pad_nops -= num_nops
                for nop in nop_codes[num_nops - 1]:
                    data.append(nop & 0xff)
                    data.append(nop >> 8 & 0xff)

            if piece.imm_bits:
                arg_bits = self.get_piece_imm(piece)
                if piece.prefix_size >= 4:
                    word = (arg_bits >> 18 & 0x3fff) | 0x4000
                    data.append(word & 0xff)
                    data.append(word >> 8 & 0xff)
                if piece.prefix_size >= 2:
                    word = (arg_bits >> 4 & 0x3fff) | 0x4000
                    data.append(word & 0xff)
                    data.append(word >> 8 & 0xff)
                patch_bits = arg_bits&(2**piece.imm_bits - 1)
                data.append(piece.data[piece.skip_size + 0] | (patch_bits & 0xff))
                data.append(piece.data[piece.skip_size + 1] | (patch_bits >> 8 & 0xff))
                data += piece.data[piece.skip_size + 2:]
            else:
                data += piece.data[piece.skip_size:]

            assert piece.offset == len(data) - len(piece.data)

        return bytes(data)

    def get_relocs(self):
        relocs = []
        for piece in self.section_pieces:
            if piece.label and not piece.found_label:
                relocs.append(Reloc(piece.label, piece.offset, piece.imm_bits, piece.imm_scale, piece.imm_relative))
        return relocs

    def get_symbols(self):
        symbols = []
        for label in self.labels.values():
            piece = self.pieces[label.piece_ix]
            if piece.section != self.section: continue
            symbols.append(Symbol(label.name, piece.offset + label.offset))
        return symbols

def assemble(source: str) -> ObjectFile:
    assembler = Assembler()
    for n, line in enumerate(source.splitlines(False)):
        lineno = n + 1
        assembler.process_line(line, lineno)
    assembler.flush()
    section_names = set(p.section for p in assembler.pieces)
    sections = []

    for section_name in section_names:
        linker = Linker(assembler.pieces, assembler.labels, section_name)
        linker.init_pieces()
        linker.layout()

        sections.append(Section(
            name=section_name,
            align=linker.get_alignment(),
            data=linker.get_data(),
            symbols=linker.get_symbols(),
            relocs=linker.get_relocs(),
        ))

    return ObjectFile(sections)

def link(objects: Sequence[ObjectFile]) -> Section:
    section_pieces = { }
    section_labels = { }

    def add_labels(section, symbols, symbol_offset, min_offset, max_offset, piece_ix) -> int:
        labels = section_labels.setdefault(section, [])
        while symbol_offset < len(symbols):
            sym = symbols[symbol_offset]
            assert sym.offset >= min_offset
            if sym.offset >= max_offset: break
            offset = sym.offset - min_offset
            labels.append(Label(sym.name, piece_ix, offset, -1))
            symbol_offset += 1
        return symbol_offset

    for obj in objects:
        for sc in obj.sections:
            pieces = section_pieces.setdefault(sc.name, [])
            relocs = sorted(sc.relocs, key=lambda r: r.offset)
            symbols = sorted(sc.symbols, key=lambda s: s.offset)
            if not relocs:
                add_labels(sc.name, symbols, 0, 0, len(sc.data), len(pieces))
                pieces.append(Piece(sc.data, "", "", 0, 0, 0, sc.align))
            else:
                symbol_offset = 0
                prev_reloc = None
                for reloc in relocs:
                    if prev_reloc:
                        assert prev_reloc.begin() < reloc.begin()
                        symbol_offset = add_labels(sc.name, symbols, symbol_offset, prev_reloc.begin, reloc.begin(), len(pieces))
                        pieces.append(Piece(
                            sc.data[prev_reloc.begin():reloc.begin()],
                            section="",
                            label=prev_reloc.name,
                            imm_relative=prev_reloc.imm_relative,
                            imm_scale=prev_reloc.imm_scale,
                            imm_bits=prev_reloc.imm_bits,
                            align=1,
                            skip_size=4))
                    else:
                        symbol_offset = add_labels(sc.name, symbols, symbol_offset, 0, reloc.begin(), len(pieces))
                        pieces.append(Piece(
                            sc.data[:reloc.begin()],
                            section="",
                            label="",
                            imm_relative=0, imm_scale=0, imm_bits=0, align=sc.align, skip_size=0))
                    prev_reloc = reloc
                symbol_offset = add_labels(sc.name, symbols, symbol_offset, prev_reloc.begin(), len(sc.data), len(pieces))
                pieces.append(Piece(
                    sc.data[prev_reloc.begin():],
                    section="",
                    label=prev_reloc.name,
                    imm_relative=prev_reloc.imm_relative,
                    imm_scale=prev_reloc.imm_scale,
                    imm_bits=prev_reloc.imm_bits,
                    align=1,
                    skip_size=4))

    all_pieces = []
    all_labels = {}
    for section, pieces in sorted(list(section_pieces.items()), key=lambda s:s[0]):
        labels = section_labels.get(section, [])
        labels = [l._replace(piece_ix=l.piece_ix + len(all_pieces)) for l in labels]
        for label in labels:
            if label.name in all_labels:
                raise AssembleError("Duplicate symbol: {}".format(label.name))
            all_labels[label.name] = label
        all_pieces += pieces

    linker = Linker(all_pieces, all_labels, "")
    linker.init_pieces()
    linker.layout(opt_n=0)

    return Section(
        name="",
        align=linker.get_alignment(),
        data=linker.get_data(),
        symbols=linker.get_symbols(),
        relocs=linker.get_relocs(),
    )

@cache
def init_disasm_map():
    disasm_map = { }
    for inst in blip.isa.insts:
        format_map = disasm_map.setdefault(inst.bit_mask, {})
        assert inst.bit_set not in format_map
        format_map[inst.bit_set] = inst
    return list(disasm_map.items())

def disassemble_section(section: Section, indent:int=2) -> str:
    offset_to_symbol = { s.offset: s.name for s in section.symbols }
    offset_to_reloc = { r.offset: r.name for r in section.relocs }
    disasm_map = init_disasm_map()
    lines = []
    indent_str = " " * indent

    imm = 0
    imm_bits = 0

    for base in range(0, len(section.data) - 1, 2):
        bits = section.data[base] | section.data[base + 1] << 8

        label = offset_to_symbol.get(base)
        if label:
            lines.append(f"{label}:")

        inst = None
        for bit_mask, inst_map in disasm_map:
            inst = inst_map.get(bits & bit_mask)
            if inst: break

        if inst:
            args = []
            for arg in inst.args:
                arg_bits = (bits >> arg.offset) & ((1 << arg.bits) - 1)
                if arg.format == "r":
                    args.append(blip.isa.Reg(arg_bits).name)
                elif arg.format == "v":
                    if inst.name != "imm":
                        imm = (imm << 4) | arg_bits
                        imm_bits = max(imm_bits + 4, inst.imm_bits)
                        signed_imm = blip.to_signed(imm, imm_bits)
                    else:
                        signed_imm = arg_bits
                    signed_imm *= inst.imm_scale
                    
                    imm_str = str(signed_imm)

                    reloc_name = offset_to_reloc.get(base)
                    if reloc_name:
                        imm_str = f"{reloc_name} ({signed_imm:+})"
                    elif inst.imm_relative:
                        sym_name = offset_to_symbol.get(base + 2 + signed_imm)
                        if sym_name:
                            imm_str = f"{sym_name} ({signed_imm:+})"

                    args.append(imm_str)
                else:
                    raise ValueError(f"Unknown arg format: {arg.format}")
            arg_str = " " + ", ".join(args) if args else ""
            lines.append(f"{indent_str}{inst.name}{arg_str}")
        else:
            lines.append(indent_str + "undef")

        if inst and inst.name == "imm":
            imm_bits += 14
            imm = (imm << 14) | (bits & 0x3fff)
        else:
            imm_bits = 0
            imm = 0

    return "\n".join(lines)

@blip.check
def check_simple():
    src = "add A, B, C"
    obj = assemble(src)
    assert len(obj.sections) == 1
    sec = obj.sections[0]
    assert len(sec.data) == 2
    assert sec.data[0] == 0b0001_0010
    assert sec.data[1] == 0b1010_0000

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, bytes):
            return binascii.b2a_hex(o).decode("ascii")
        return super().default(o)

@blip.check
def check_linker():
    src1 = """
        .section code
        main:
            mov Y, 120
            bsr print
            ret
        .section data
        message:
            .asciz "Hello!"
    """

    src2 = """
        .section code
        print:
            apc X, message
            bsr strlen
            sys 0x10000
            ret
        strlen:
            ret
    """

    obj1 = assemble(src1)
    obj2 = assemble(src2)
    binary = link([obj1, obj2])
    disasm = disassemble_section(binary)

    assert "bsr print" in disasm
    assert "bsr strlen" in disasm
    assert "apc X, message" in disasm
    assert "sys 65536" in disasm
