import argparse
import sys

parser = argparse.ArgumentParser("blip")
parser.add_argument("--check", type=str, help="Run checks in module")
argv = parser.parse_args(sys.argv[1:])

import blip.isa.enums
import blip.isa.insts
import blip.verification as verification

if argv.check:
    for check in verification.all_checks:
        if not check.name.startswith(argv.check): continue
        print(f"{check.name}: ", end="", flush=True)
        check.func()
        print("OK")
        for line in verification.info_lines:
            print(" .. " + line)
        verification.info_lines.clear()
