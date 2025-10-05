# crypto / zkwarmup

A challenge from Buckeye CTF 2024

### Description

I just think zero-knowledge proofs are kinda neat

nc challs.pwnoh.io 13421

File: [zkwarmup.py](./zkwarmup.py)

### Solve

Apparently this challenge was solvable not in the intended way because the challenge author put a `random.seed()` before the creation of x rather than before the assignments of bits. So you could find x through a PRNG attack rather than in the intended mode.

However, it was still a fun challenge trying to determine how to prove I knew x. I ended up realizing that if b was 1, I just needed s = z<sup>2</sup>. However, if b was 0, it wasn't so easy because it introduced y. But since I knew sqrt(y), I could just send s = z<sup>2</sup> and z = ix where i was some integer.

Solve script:
```py
import random, time
from pwn import *

# I think you just need to catch the time to predict what the x value will be

p = remote('challs.pwnoh.io', 13421)

p.recvline()
n = int(p.recvline().decode().split('= ')[1])

random.seed(int(time.time()))
x = random.randrange(1, n)
y = pow(x, 2, n)
their_y = int(p.recvline().decode().split('= ')[1])
assert y == their_y

# since we're just checking a value squared, we can use x and y combined with incrementing i and i^2 to proof

i = 2

for _ in range(128):
    b = random.randrange(2)

    if b == 0:
        z = i * x
        s = pow(i, 2)
    else:
        z = i
        s = pow(i, 2)
    i += 1
    p.recvuntil(b'Provide s: ')
    p.sendline(str(s).encode())
    p.recvuntil(b'z: ')
    p.sendline(str(z).encode())
    print(p.recvline())

p.interactive()
```

Flag: `bctf{c4n_s0m30ne_g1v3_m3_a_r3a1_c01n_t0_fl1p}`

### Actual solve

The challenge author sent the actual intended solve later, so I feel obligated to pay some homage to it, since it's a novel solution:

"Simple implementation of zero-knowledge proof for quadratic residues. Vulnearbility is usage of predictable time-based random seed

"To solve, predict the coin flips and cheat the proof with specially chosen values.

"If b = 1, pick any *z* and let *s* = *z*<sup>2</sup>

"If b = 0, pick any *s* = *y*<sup>*c*</sup> where *c* is an odd number. Then *z*<sup>2</sup> = *y*<sup>*c*</sup>(*y*) = *y*<sup>(*c*+1)/2</sup>, which is easily computable since (*c*+1) is even.