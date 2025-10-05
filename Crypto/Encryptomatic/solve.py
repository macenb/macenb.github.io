from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import *

#I NEED TO AUTOMATE THIS
ascii_text_chars = list(range(97, 122)) + [32, 95, 123, 125] + list(range(48, 57)) + list(range(65, 90))
#uses the ord range of all lowercase letters, ' ', '_', '{', '}', all numbers, and capital letters for a brute force

#length of string is 32

def bruteforce_letter(plaintext):

    p = remote("0.cloud.chals.io", 28962)

    p.recvuntil(b"> ")

    #pad
    padding = 'a' * (15 - (len(plaintext) % 16))
    if len(padding) == 0:
        padding = 'a' * 16
    
    temptext = padding + plaintext

    #send get request
    p.sendline(padding.encode())
    r = p.recvline().decode().strip().lstrip("> Encrypted: ")

    #cut the text to 
    if len(plaintext) < 15:
        match = r[0:32]
    elif len(plaintext) < 31:
        match = r[32:64]
    else:
        match = r[64:64+32]
    # print(match)

    #bruteforce through all the letters
    for letter in string.printable:
        #add the new letter to the hex
        temp = temptext + letter
        p.sendline(temp.encode())

        #prep the new get request
        if len(plaintext) < 15:
            spoof = p.recvline().decode().strip().lstrip("> Encrypted: ")[0:32]
        elif len(plaintext) < 31: 
            spoof = p.recvline().decode().strip().lstrip("> Encrypted: ")[32:64]
        else: 
            spoof = p.recvline().decode().strip().lstrip("> Encrypted: ")[64:64+32]

        #if it matches, recurse
        if spoof == match:
            if letter == "}":
                print(plaintext + letter)
                break
            else:
                print(plaintext + letter)
                if len(plaintext + letter) == 15:
                    print("15")
                p.close()
                bruteforce_letter(plaintext + letter)
                break

bruteforce_letter("")
# SIVUSCG{3CB_sl1d3_t0_th3_l3ft}

# for some reason, it quits every once in a while and I have to restart the script. No idea why