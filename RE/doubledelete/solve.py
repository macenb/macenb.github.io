
with open("flag.txt.enc", "rb") as f:
   encflag = f.read()

flag = b''
for i in range(0, len(encflag), 4):
    dig = bin(int.from_bytes(encflag[i:i+4],'little'))[2:]
    # dig = bin(int(bytes.hex(encflag[i:i+4]), 16))[2:]
    while len(dig) != 32:
        dig = '0' + dig
    dig = dig[-13:] + dig[:-13]
    for j in range(len(dig)-8, -1, -8):
        flag += bytes([int(dig[j:j+8], 2)])
print(flag)
