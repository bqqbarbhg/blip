import argparse
import sys

parser = argparse.ArgumentParser("blip")
parser.add_argument("--check", type=str, help="Run checks in module")
argv = parser.parse_args(sys.argv[1:])

if argv.check:
    import blip.isa.enums
    import blip.isa.insts
    import blip.isa.emu
    import blip.verification as verification

    for check in verification.all_checks:
        if not check.name.startswith(argv.check): continue
        print(f"{check.name}: ", end="", flush=True)
        check.func()
        print("OK")
        for line in verification.info_lines:
            print(" .. " + line)
        verification.info_lines.clear()
