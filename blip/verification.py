from collections import namedtuple
from typing import Callable

Check = namedtuple("Check", "name func")

all_checks: list[Check] = []
info_lines: list[str] = []

def check(fn: Callable) -> Callable:
    name = f"{fn.__module__}.{fn.__name__}"
    check = Check(name, fn)
    all_checks.append(check)
    return fn

def info(msg: str) -> None:
    info_lines.append(msg)
