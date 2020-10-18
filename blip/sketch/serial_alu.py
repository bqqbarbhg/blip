import blip

def divide_serial_uu(a: int, b: int) -> (int, int):

    # Only defined for 32-bit unsigned inputs
    assert 0 <= a <= 0xffff_ffff
    assert 0 <= b <= 0xffff_ffff

    # Initialize 64-bit remainder to a:0 and quotinent to 0
    rem_lo, rem_hi = a, 0
    quot = 0
    for n in range(32):
        # Shift remainder bit per bit and subtract the divisor
        # every time it "fits" the remainder, outputting a quotinent bit.
        rem_hi = (rem_hi << 1) | ((rem_lo >> 31) & 1)
        rem_lo <<= 1
        quot <<= 1
        rem = rem_hi - b
        if rem >= 0:
            rem_hi = rem
            quot |= 1

    return (quot, rem_hi)

@blip.check
def check_simple_divide_uu():
    for a in blip.gen_fixtures(32, 500):
        for b in blip.gen_fixtures(32, 100):
            if b == 0: continue
            q, r = divide_serial_uu(a, b)
            assert q == a // b
            assert r == a % b

