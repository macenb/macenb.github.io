This challenge was actually really cool, and it's been my first experience of a hash extension challenge in a CTF

So basically what a hash extension is, is based on a known initial string, initial hash, and length of a secret, you can extend an existing hash to use the same secret but an extended string. The Python file included called [hlextend.py](./hlextend.py) is from a GitHub that ended up working. The compiled C file is also from a different GitHub but it didn't work.

# TagSeries3

A challenge from WolvCTF 2024

### Description:

Surely they got it right this time.

nc tagseries3.wolvctf.io 1337

File: 
- [chal.py](./chal.py)

### Solve

This challenge is similar to TagSeries1 in that we need to match plaintext to ciphertext to get the flag. However, this time we have only one chance and we have to match the plaintext to its hash appended to some unknown secret, which seems much harder. However, Sha1 is vulnerable to something called a Hash Length Extension attack. This is an attack where you can take some hash where you know the original hash, the original text appended to a secret, and a knowledge of the length of the original secret and generate a new hash that has your desired plaintext attached to it.

I searched for some hash extension libraries online for a while and found some that didn't work, but I finally found a Python solution that worked really well! 

- [hlextend](https://github.com/stephenbradshaw/hlextend/tree/master)

So I just attached this and pertinent information from the initial query into a solve script that worked!

```python
from pwn import *
import hlextend

p = remote("tagseries3.wolvctf.io", 1337)
p.recvline()
oghash = p.recvline().rstrip(b"\n").decode()

sha = hlextend.new('sha1')
newstring = sha.extend(b'flag.txt', b'GET FILE: ', 1200, oghash)
signature = sha.hexdigest()

p.sendline(newstring)
p.sendline(signature)
p.interactive()
```

Flag: `wctf{M4n_t4er3_mu5t_b3_4_bett3r_w4y}`