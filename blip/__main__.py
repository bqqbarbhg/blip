import argparse
import sys
import time

parser = argparse.ArgumentParser("blip")
parser.add_argument("--check", type=str, help="Run checks in module")
argv = parser.parse_args(sys.argv[1:])

if argv.check:
    import blip.isa.enums
    import blip.isa.insts
    import blip.isa.emu
    import blip.rtl.alu
    import blip.rtl.alu_ideal
    import blip.verification as verification

    for check in verification.all_checks:
        if not check.name.startswith(argv.check): continue
        print(f"{check.name}: ", end="", flush=True)
        begin = time.perf_counter()
        check.func()
        end = time.perf_counter()

        duration = end - begin
        unit = "s"
        if duration < 0.1:
            duration *= 1e3
            unit = "ms"

        pad = " " * (60 - len(check.name))
        print(f"OK {pad}{duration:6.2f}{unit}")
        for line in verification.info_lines:
            print(" .. " + line)
        verification.info_lines.clear()
