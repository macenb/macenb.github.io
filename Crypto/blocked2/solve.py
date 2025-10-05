
# from Crypto.Util.strxor import strxor

# iv = bytes.fromhex("642914f52c44a2a26b86818b51fc59fb")
# ct = bytes.fromhex("642914f52c44a2a26b86818b51fc59fbd017ea3f846663db7fbf0532d20efc890c3c43cfaccefdf1487cfebb2833ec88957c54f0043297a1fe8d3be7541d9176f5db393a687c0b0779b860ee899650721033f9121c0b36d4e5444dd7cea6bf10566f4c88d07081cee8660dfadfa5c84517b09816e9f112f67ee4e3cddc5041b36357e83f054df420a0566eabe4cafe659056399911481c1103d78604f3a86f57c5eab55c5b6178d166c81f1293abecbe9b2107559c3c42bb03281bdcf8bcd8906406de785fd725fb769dd6d030b79cec59511b3346ffd224bb47622b02738978b62e83db1a8cd5cbbe2ba5961f660be05af593d4ede634da1d9d6ff77ac0a0741cc1a34cebfe66e3ecc7351bf35748be8df114b45acfea7414d2e0f8525a0e30382974e1b0bf0af153f58f2caad35626")
# ecn = bytes.fromhex("073c60638dd100fd8186203bd24e0853a87a8169450b1d1c2fbfded33552578fa47f854ce14614b413c97657b12e92ec")

# blocks = [ecn[i:i+16] for i in range(0, len(ecn), 16)]
# ctblocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
# print(strxor(blocks[2], ctblocks[1]))

from pwn import *

p = remote('blocked2.wolvctf.io', 1337)
message = b''

p.recvuntil(b'message:\n')

enc_flag = p.recvline().decode()[:-1]
blocks = [enc_flag[i:i+32] for i in range(0, len(enc_flag), 32)]

# print(enc_flag)
# print(blocks)

start = False
for i in range(len(blocks)-1):
    p.recvuntil(b'> ')
    if not start:
        start = True
        p.sendline(blocks[0].encode())
    else:
        #print(message,message[-16:].hex())
        p.sendline(message[-16:].hex().encode())
    out = p.recvline().decode()[:-1][-32:]
    # print(out)

    pt1 = xor(bytes.fromhex(out), bytes.fromhex(blocks[i+1]))
    #print(pt1)
    message += pt1

print(message)
p.interactive()