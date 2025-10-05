# crypto / hashbrown

A challenge from Buckeye CTF 2024

### Description

I made fresh hashbrowns fresh hash function.

nc challs.pwnoh.io 13419

File: [hashbrown.py](./hashbrown.py)

### Solve

This challenge is based on this function for aes encryption:

```py
def aes(block: bytes, key: bytes) -> bytes:
    assert len(block) == len(key) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)
```

It takes the key and block and ecb encrypts. That function is used in conjunction with these two to encrypt data:

```py
def hash(data: bytes):
    data = pad(data)
    state = bytes.fromhex("f7c51cbd3ca7fe29277ff750e762eb19")

    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        state = aes(block, state)

    return state


def sign(message, secret):
    return hash(secret + message)
```

It takes their message and secret, uses a secret for a nonce, and encrypts it in a Fiestel manner (hopefully I'm using that right). If we need to encrypt our own data, we would need the secret to start off the message, but we don't have that. However, since the program prints out the final hash, we can just append 'french fry' onto their message (padded) and aes encrypt our last block with their hash to forge a hash and get the flag:

```py
from hashbrown import *
from pwn import *


message = pad(my_message) + b"french fry"
p = remote("challs.pwnoh.io", 13419)
p.recvuntil(b"hex:\n")
hexmsg = p.recvline()
print(bytes.fromhex(hexmsg.decode().strip()))
# quit()
p.recvuntil(b"Signature:\n")
signature = p.recvline().decode().strip()
print(signature)

p.recvuntil(b"> ")
p.sendline(bytes.hex(message).encode())
# print(message)
p.recvuntil(b"> ")
p.sendline(bytes.hex(aes(pad(b'french fry'), bytes.fromhex(signature))).encode())

p.interactive()
```

Flag is: `bctf{e7ym0l0gy_f4c7_7h3_w0rd_hash_c0m35_fr0m_7h3_fr3nch_hacher_wh1ch_m34n5_t0_h4ck_0r_ch0p}`