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

# https://github.com/stephenbradshaw/hlextend/tree/master