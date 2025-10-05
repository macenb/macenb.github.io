# TagSeries1

A challenge from WolvCTF 2024

### Description:

Don't worry, the interns wrote this one.

nc tagseries1.wolvctf.io 1337

Files:
- [chal.py](./chal.py)

### Solve:

So as we see in the challenge script, this challenge on remote will accept input in two lines, some plaintext and its last block of ciphertext. If the ciphertext does in fact correspond to the plaintext, then we get a flag. We, however, can't repeat plaintexts.

Since the encryption is AES ECB, there is no jumbling based on past blocks, so if we pass just the last block of plaintext, we can find the tag associated with our total plaintext. I just wrote a simple solve script for it:

```python
from pwn import *

p = remote('tagseries1.wolvctf.io', 1337)

p.recvline()

p.sendline(b"xt" + b"a" * 14)
p.sendline(b'a' * 16)
tag = p.recvline().rstrip(b"\n")

p.sendline(b"GET FILE: flag.txt" + b"a" * 14)
p.sendline(tag)
p.interactive()
```

Flag: `wctf{C0nGr4ts_0n_g3tt1ng_p4st_A3S}`