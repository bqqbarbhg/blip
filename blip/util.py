import blip

def to_signed(val, bits):
    sign_bit = (1 << (bits - 1))
    if val & sign_bit:
        return -((~val + 1) & ((sign_bit<<1) - 1))
    else:
        return val & (sign_bit - 1)

@blip.check
def check_to_signed():
    for bits in range(1, 16):
        mask = (1 << bits) - 1
        for n in range(-2**(bits-1), 2**(bits-1)):
            unsigned = n & mask
            signed = to_signed(unsigned, bits)
            assert signed == n
