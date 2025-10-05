from pwn import *

p = remote('tagseries1.wolvctf.io', 1337)

p.recvline()
# p.sendline(b"GET FILE: flag.t")
# p.sendline(b"a"*16)
# pt1 = p.recvline().rstrip(b"\n")

p.sendline(b"xt" + b"a" * 14)
p.sendline(b'a' * 16)
pt2 = p.recvline().rstrip(b"\n")

p.sendline(b"GET FILE: flag.txt" + b"a" * 14)
p.sendline(pt2)
p.interactive()

# ECB cut and paste