from collections import namedtuple
from typing import Callable
from typing import Iterator
from dataclasses import dataclass
import time

Check = namedtuple("Check", "name func")

all_checks: list[Check] = []
info_lines: list[str] = []

extra_fixtures = 1.0

def check(fn: Callable) -> Callable:
    name = f"{fn.__module__}.{fn.__name__}"
    check = Check(name, fn)
    all_checks.append(check)
    return fn

def info(msg: str) -> None:
    info_lines.append(msg)

def gen_fixtures32() -> Iterator[int]:
    yield from (0, 1, 2, 3)
    yield from (0xffff_fffc, 0xffff_fffd, 0xffff_fffe, 0xffff_ffff)
    yield from (100, 0xaaaa_aaaa, 123456789, 0xffff_0000)
    for n in range(32):
        yield 1 << n
    for n in range(32):
        yield (1 << (n + 1)) - 1
    for n in range(32):
        yield (0xffff_ffff << (31 - n)) & 0xffff_ffff
    for n in range(84):
        yield n*n*n*n
        yield 0xffff_ffff - n*n*n*n
    for n in range(256):
        yield n
        yield n << 8
        yield n << 16
        yield n << 24
    for n in range(1600):
        yield n*n*n
        yield 0xffff_ffff - n*n*n
    for n in range(65536):
        yield n*n
        yield 0xffff_ffff - n*n
    for n in range(2**32):
        yield n

def gen_fixtures(bits: int, num: int, dim: int) -> Iterator[int]:
    assert bits <= 32
    num = int(num * extra_fixtures ** (1 / dim))
    # TODO: Switch generator based on bits
    gen = gen_fixtures32()
    mask = (1 << bits) - 1
    for v in gen:
        if num <= 0: break
        yield v & mask
        num -= 1

@dataclass
class CheckOptions:
    extra_fixtures: float

@dataclass
class CheckResult:
    name: str
    duration: float
    info_lines: str

def init_checks(opts: CheckOptions):
    global extra_fixtures
    extra_fixtures = opts.extra_fixtures

def run_check(check: Check) -> CheckResult:
    global info_lines
    begin = time.perf_counter()
    check.func()
    end = time.perf_counter()
    duration = end - begin
    lines = info_lines
    info_lines = []
    return CheckResult(name=check.name, duration=duration, info_lines=lines)
