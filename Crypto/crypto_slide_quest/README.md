# Crypto Slide Quest

A challenge from Square CTF 2023

### Description:

I lost my secret key and the flag while writing this challenge, can you help me out? Ciphertext base64: LEs2fVVxNDMfNHEtcx80cB8nczQfJhVkDHI/Ew==

[crypto_slide_quest.c](./crypto_slide_quest.c)

### Solve

Idk who decided to write a crypto challenge in C, but interesting decision. This made the challenge a bit tricky, because you have to realize that in C, a 7 length string actually has a length of 6, since the last index is taken by a null byte.

Let's take a look at the encryption file:

```c
#include "flag.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    _Static_assert(sizeof(key) == 7, "Invalid key size!");

    char* output = malloc(sizeof(flag));
    strncpy(output, flag, sizeof(flag));

    int flag_len = strlen(flag);
    int key_len = strlen(key);

    for(int i = 0; i < flag_len - key_len + 1; i++) {
        for(int j = 0; j < key_len; j++) {
            output[i + j] ^= key[j];
        }
    }


    printf("%s", output);
    free(output);
    return 0;
}

```

So, like I said before, the file uses a key with a size of 7, which in C means that it actually has a size of six. So for the flag, we need to find a key that is six characters long. The actual encryption happens through a series of xor operations. It's a bit complicated so let's explain it:

The for loops work through the flag repeatedly for the flag. First, it takes the first character of the flag (and the correlated characters after it as we'll see) and steps into the second for loop. This takes each character of the flag starting with character i as passed by the first for loop and xors each character of the flag with the associated character. This continues for each character of the flag. Understanding this gives us a couple important pieces of information:

First, we need to remember that xor is commutative and associative (meaning order doesn't matter), and it's self inverse. This means if a ^ b = c and c ^ b = a, or in other words, if you have any two values of an xor, you can find the third.

If we take a closer look at the xor, we find that it follows a very specific pattern of encryption that will let us determine the key of the XOR. Because we are starting the xor of the whole key at the character of the flag we are currently on in the for loop, we have an exploitable pattern. The final xor looks something like this:

```
flag{.......
keyval
xxxxxxxxxxxxxx
.keyval
xyyyyyyyyyyyyy
..keyval
xyzzzzzzzzzzzz
```
And so forth. So the first value of our encrypted flag has only been xored by the first value of our key. Once we determine this, we can realize that our second value has only been xored by the first and second value of our key, so once we learn the first value we can determine the second. This pattern can be used to find all the characters of the key, since we know the first, second, and last characters of the flag. Here is the solve script:

```py
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
```

Flag: `flag{1ts_t1m3_t0_g3t_fUnkee}`