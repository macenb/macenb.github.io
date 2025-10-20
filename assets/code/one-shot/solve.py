from z3 import *

SIZE_FLAG = 27*6

# Define unknown variable
r1 = [BitVec(f'v{i}', 8) for i in range(SIZE_FLAG)]

# Create solver
solver = Solver()

for i in range(SIZE_FLAG):
    solver.add(r1[i] >= 0x20, r1[i] <= 0x7e)  # Printable ASCII range

### Add conditions here
# first part of flag
r3 = [121, 105, 121, 122, 103, 98, 70, 112, 41, 112, 102, 40, 105, 44, 112, 127, 47, 42, 112, 46, 105, 117, 112, 125, 46, 123, 41]
for r2 in range(27):
    solver.add(r1[r2] ^ (r1[r2] >> 1) == r3[r2])

# second part of flag
r4 = [59, 60, 82, 46, 58, 91, 53, 75, 98, 75, 91, 94, 54, 67, 82, 50, 79, 57, 51, 47, 92, 91, 68, 56, 77, 57, 80]
for r2 in range(27):
    r3 = (r2 - 13) //2
    if r2 & 1 == 0:
        r3 *= -1
    solver.add(r1[27+r2] + r3 == r4[r2])

def base69_to_bytes(digits):
    """
    Convert a list of base-69 digits to a byte sequence.

    digits: list of integers, each 0..68, most significant digit first
    returns: bytes
    """
    base = 69
    # Convert base-69 digits to a single integer
    value = 0
    for d in digits:
        if not (0 <= d < base):
            raise ValueError(f"Digit out of range: {d}")
        value = value * base + d

    # Determine how many bytes are needed to represent the number
    n_bytes = (value.bit_length() + 7) // 8
    return value.to_bytes(n_bytes, byteorder='big')


# third part of flag
r4 = [63, 43, 39, 12, 19, 36, 61, 6, 34, 50, 63, 61, 54, 53, 24, 37, 59, 44, 46, 66, 55, 57, 13, 59, 41, 11, 13, 15, 53, 23, 51, 22, 64, 0, 32]
b = base69_to_bytes(r4)
for i in range(len(b)):
    solver.add(r1[27*2 + i] == b[i])

# fourth part of flag
r4 = '\n========================\n  THE E†IGMA OF HEAVEN\n========================\n\nPRAISE THE LORD! The air conditioner †eeps them away it sings gospels and\n†RAISE THE LORD! Finding faith in wh†te noise.\nPRAISE THE LORD! The messages are coming in loud and clear †nd\nI hear them and I see them in t†e sky the towers are sending messages and\nI hear them and I see them.\nPRAISE T†E LORD! The people in the parkin† lot can\'t hurt me anymore\nthey can\'t †urt me anymore their words are weak and the lord is strong.\nPRAISE THE LORD! T†e bible shows the way and the way prot†cts me and\nI\'ve seen the messag†s and I heart them and I see them and they can\'t\nhurt me anymore.\nPRAISE THE L†RD!\n\nCHAPTERS:                        †        ╔═══════════════╗\n—————————                    †            ║               ║\nI. T†e Enigma of Heaven:                  ║    HEAVEN     ║\n 9,999,999 Channels, Fi†ding Faith        ╟───────────────╢\n in White Noise... The God St†mulation!   ║               ║\nII. †he Hierarchy of Equality:            †   RADIATION   ║\n Angelic Voices†Echo Through the Halls    ╟─────────†─────╢\n of Heaven, Under the Railroad †ridge     ║               ║    "And I have\nIII. The Paradox of Fa†th:                ║     RADIO     ║      told you\n There\'s a Knocking a† the Door!          ╟──────†────────╢     the TRUTH,\n God is in, God is in!                    ║          †    ║\nIV. The Senselessness of Endlessness:     ║  TELEVISION   ║      for you\n Returning to an Empty Apartment          ║               ║   are my child,\n with a Grocery Store Guardian Angel      ╚═══════════════╝    and you have\n                                                              seen my face"\n\nAn EP titled "The Enigma of Heaven and Other Daily Delusions" '
indices = [i for i, c in enumerate(r4) if c == "†"]
print(len(indices))
print(indices)
r3 = 0
for r2 in range(27):
    solver.add(r1[27*3 + r2] + r3 - 16 == indices[r2])
    r3 = indices[r2]

# fifth part of flag - line 1552, not sure how this is deterministic
# this is actually morton encoding apparently
# r4 = [1611216, 946813, 716893, 716989, 488303, 939977, 1175675, 1391467, 1391323]
# for r2 in range(9):
#     r6 = (r1[27*4 + r2*3] | (r1[27*4 + r2*3] << 16)) & 50331903
#     r6 = (r6 | (r6 << 8)) & 50393103
#     r6 = (r6 | (r6 << 4)) & 51130563
#     r6 = (r6 | (r6 << 2)) & 153391689
#     r5 = r6
#     r6 = (r1[27*4 + r2*3 + 1] | (r1[27*4 + r2*3 + 1] << 16)) & 50331903
#     r6 = (r6 | (r6 << 8)) & 50393103
#     r6 = (r6 | (r6 << 4)) & 51130563
#     r6 = (r6 | (r6 << 2)) & 153391689
#     r5 = r5 | (r6 << 1)
#     r6 = (r1[27*4 + r2*3 + 2] | (r1[27*4 + r2*3 + 2] << 16)) & 50331903
#     r6 = (r6 | (r6 << 8)) & 50393103
#     r6 = (r6 | (r6 << 4)) & 51130563
#     r6 = (r6 | (r6 << 2)) & 153391689
#     r5 = r5 | (r6 << 2)
#     solver.add(r5 == r4[r2])
    # solver.add(r1[27*4 + r2*3] in list(range(0x30, 0x40)) + list(range(0x41, 0x5b)) + [ord('_'), ord(','), 0x7d])

def compact3(v):
    v &= 0x09249249  # binary: 00001001001001001001001001001001
    v = (v | (v >> 2)) & 0x030c30c3
    v = (v | (v >> 4)) & 0x0300f00f
    v = (v | (v >> 8)) & 0xff
    return v

def unmorton3(m):
    x = compact3(m)
    y = compact3(m >> 1)
    z = compact3(m >> 2)
    return x, y, z

r4 = [1611216, 946813, 716893, 716989, 488303, 939977, 1175675, 1391467, 1391323]
fleg = []
for v in r4:
    for i in unmorton3(v):
        fleg.append(i)

for i in range(27):
    solver.add(r1[27*4 + i] == fleg[i])

# sorting algorithm for the last part
# r2 = []
# # start, end, state
# r3 = [(0, 26, 0)]
# while len(r3) > 0:
#     r4, r5, r6 = r3[-1]
#     r7 = (r4 + r5) // 2
#     if r4 >= r5:
#         r3 = r3[:-1]
#         continue
#     if r6 == 0: # split in half
#         r3 = r3[:-1] + [(r4, r5, 1)]
#         r3 = r3 + [(r4, r7, 0)]
#         continue
#     if r6 == 1: # handle right half
#         r3 = r3[:-1] + [(r4, r5, 2)]
#         r3 = r3 + [(r7 + 1, r5, 0)]
#         continue
#     if r6 == 2: # compare and maybe swap
#         if r1[r0][r5] < r1[r0][r7]:
#             r1 = r1[:r0] + [r1[r0][:r7] + [r1[r0][r5]] + r1[r0][r7+1:r5] + [r1[r0][r7]] + r1[r0][r5 + 1:]] + r1[r0 + 1:]
#             r2 = r2 + [(r7, r5)]
#         r3 = r3[:-1] + [(r4, r5, 3)]
#     if r6 == 3: # shrink range and repeat
#         r3 = r3[:-1] + [(r4, r5-1, 0)]
last = '3_C0MP0N3N7_7H47_N33D5_17_}'
for i in range(27):
    solver.add(r1[27*5 + i] == ord(last[i]))


# Solve
if solver.check() == sat:
    model = solver.model()
    chars = [chr(model[v].as_long()) for v in r1]
    print(''.join(chars).encode())
else:
    print("No solution exists.")
