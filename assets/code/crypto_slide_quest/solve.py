from base64 import b64decode

ct = b64decode("LEs2fVVxNDMfNHEtcx80cB8nczQfJhVkDHI/Ew==")

key_len = 6
flag_len = len(ct)

def crack(key, cipher):
    cyt = cipher
    for i in range(flag_len - key_len + 1):
        for j in range(key_len):
            cyt[i + j] ^= key[j]
    cytext = ''.join([chr(i) for i in cyt])
    return cytext

def xors(flag):
    final = 0
    if len(flag) == 0: return final
    for i in flag:
        final ^= ord(i)
    return final

def break_key(cipher):
    key = ''
    flag = 'flag{'
    for i in range(5):
        key += chr(ord(flag[i]) ^ cipher[i] ^ xors(key))
    key += chr(ct[-1] ^ ord('}'))
    return key


if __name__ == "__main__":
    key = break_key(ct)
    key = key.encode()

    ciphertext = [i for i in ct]

    print(crack(key, ciphertext))