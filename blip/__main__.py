import argparse
import sys
import multiprocessing
import os
import blip.verification as verification

import blip.isa.enums
import blip.isa.insts
import blip.isa.emu
import blip.rtl.alu
import blip.rtl.alu_ideal
import blip.sketch.serial_alu

parser = argparse.ArgumentParser("blip")
parser.add_argument("--check", type=str, help="Run checks in module")
parser.add_argument("--fixtures", type=float, default=1, help="Multiplier on fixtures to use everywhere")
parser.add_argument("--threads", "-j", type=int, default=1, help="Number of threads to use")
argv = parser.parse_args(sys.argv[1:])

def process_result(result: verification.CheckResult):
    duration = result.duration

    unit = "s"
    if duration < 0.1:
        duration *= 1e3
        unit = "ms"

    pad = " " * (60 - len(result.name))
    print(f"{result.name}: OK{pad}{duration:6.2f}{unit}")
    for line in result.info_lines:
        print(" .. " + line)
    sys.stdout.flush()

if argv.check:
    opts = verification.CheckOptions(extra_fixtures=argv.fixtures)
    verification.init_checks(opts)

    num_threads = argv.threads
    if num_threads == 0:
        num_threads = os.cpu_count()

    active_checks = [c for c in verification.all_checks if c.name.startswith(argv.check)]
    print(f"Found {len(active_checks)} checks, running with {num_threads} threads")

    if num_threads > 1:
        with multiprocessing.Pool(num_threads, verification.init_checks, (opts,)) as pool:
            for result in pool.imap_unordered(verification.run_check, active_checks):
                process_result(result)
    else:
        for check in active_checks:
            result = verification.run_check(check)
            process_result(result)
 