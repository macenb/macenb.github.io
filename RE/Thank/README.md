# rev / thank

A challenge from Buckeye CTF 2024

### Decription

I am so grateful for your precious files!

nc challs.pwnoh.io 13373

File: [thank](./thank)

###

This challenge actually decompiled really well in Binja. You could quickly see that it requested a file be sent and then loaded in the library and ran it. Here are some code snippets:

```c
int64_t sub_401570(int64_t arg1) {
    void* fsbase
    int64_t rax = *(fsbase + 0x28)
    void s
    snprintf(&s, maxlen: 0x20, format: &data_402044, arg1)
    int64_t rax_2 = dlopen(&s, 1)
    int64_t rax_3
    
    if (rax_2 != 0)
        rax_3 = dlsym(rax_2, "thank")
    
    if (rax_2 == 0 || rax_3 == 0)
        puts(str: "Thanks for your file!")
    else
        rax_3()
    
    *(fsbase + 0x28)
    
    if (rax == *(fsbase + 0x28))
        return 0
    
    __stack_chk_fail()
    noreturn
}

```

Anyway, the challenge solution was just to compile a `.so` file with a symbol `thank`, which the binary would then run and print the output, as seen by the `dlopen()` and `dlsym()` calls. So I wrote some C code:

```c
#include <stdio.h>
#include <stdlib.h>

int thank() {
    // open flag.txt in the same directory
    FILE *flag = fopen("flag.txt", "r");
    if (flag == NULL) {
        printf("Flag file not found.\n");
        return 1;
    }

    char buffer[64];

    while (fgets(buffer, sizeof(buffer), flag)) {
        printf("%s", buffer);
    }

    fclose(flag);
    return 0;
}
```

Compiled it with a handy command for `.so` files:

```sh
gcc -shared -o libshared.so -fPIC dev_thank.c
```

Then I sent it with pwntools and it output the flag:

```py
from pwn import *

p = remote("challs.pwnoh.io", 13373)

file_contents = open("libshared.so", "rb").read()
print(file_contents)

p.recvuntil(b"bytes)? ")
p.sendline(str(len(file_contents)).encode())

p.recvuntil(b"file!\n")
p.send(file_contents)

p.interactive()
```

Then it just output the flag: `bctf{7h4nk_y0ur_10c41_c0mpu73r_70d4y}`