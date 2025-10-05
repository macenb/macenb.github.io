# doubledelete's revenge

A challenge from WolvCTF 2024

### Description:

The notorious WOLPHV group has re-emerged and doubledelete is now ransoming us for our flags! Can you help us so we don't have to pay them?

Files:
- [flag.txt.enc](./flag.txt.enc)
- [reveng1](./reveng1)

### Solve:

Starting with the basics, I just took a look to see what kind of file this was:

```sh
overllama@computer:doubledelete$ file reveng1
reveng1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2ce26489d5798dda857db7bbc3309ba20a592fec, for GNU/Linux 3.2.0, not stripped
```

So we see it's an ELF executable, 64 bit, dynamically linked, AND not stripped, so nothing too fancy. Next step, open this up in Ghidra for a quick look.

```c
undefined8 main(int param_1,undefined8 *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  FILE *pFVar3;
  uint *puVar4;
  long in_FS_OFFSET;
  int local_64;
  uint local_48 [14];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 3) {
    pFVar3 = fopen((char *)param_2[1],"r");
    fread(local_48,1,0x30,pFVar3);
    for (local_64 = 0; local_64 < 0xc; local_64 = local_64 + 1) {
      puVar4 = (uint *)((long)local_48 + (long)(local_64 << 2));
      uVar1 = *puVar4;
      *puVar4 = uVar1 << 0xd | uVar1 >> 0x13;
    }
    pFVar3 = fopen((char *)param_2[2],"wb");
    fwrite(local_48,1,0x30,pFVar3);
    uVar2 = 0;
  }
  else {
    printf("[wolphvlog] usage: %s <infile> <ofile>",*param_2);
    uVar2 = 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

The only thing in this is one main function that looks like it just scrambles up some text from an input file, then writes it to an output file. I know it's mixing it in the for loop that runs `0xc` times, but Ghidra doesn't make it super clear what is happening. The disassembled code actually really helps us here.

This is the entire block of assembly related to the encryption function:

```
0x0000000000001260 <+151>:   mov    eax,DWORD PTR [rbp-0x5c]
0x0000000000001263 <+154>:   shl    eax,0x2
0x0000000000001266 <+157>:   cdqe
0x0000000000001268 <+159>:   lea    rdx,[rbp-0x40]
0x000000000000126c <+163>:   add    rax,rdx
0x000000000000126f <+166>:   mov    QWORD PTR [rbp-0x48],rax
0x0000000000001273 <+170>:   mov    rax,QWORD PTR [rbp-0x48]
0x0000000000001277 <+174>:   mov    eax,DWORD PTR [rax]
0x0000000000001279 <+176>:   rol    eax,0xd
0x000000000000127c <+179>:   mov    edx,eax
0x000000000000127e <+181>:   mov    rax,QWORD PTR [rbp-0x48]
0x0000000000001282 <+185>:   mov    DWORD PTR [rax],edx
0x0000000000001284 <+187>:   add    DWORD PTR [rbp-0x5c],0x1
0x0000000000001288 <+191>:   cmp    DWORD PTR [rbp-0x5c],0xb
0x000000000000128c <+195>:   jle    0x1260 <main+151>
```

14 lines. Not a whole ton to deal with here. We start by loading in a section of our plaintext (based on some incrementing value multiplied by 4, so we're working with 4 byte chunks), then we take those four bytes and this is the only line that edits them: `rol eax,0xd`. It's just a rotate left. We can undo that!

I wrote a Python script for this, and the basic concept is that we'll open the file and just rotate every 4 bytes right (the reverse of the `rol`) by `0xd` to undo the encryption.

Here is the script:

```python
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
```

I had a broken script at first, which is why I'm writing this write up. So the commented out line above broke my script because I forgot to load the bytes as little endian, so when I performed the shift, it just re-jumbled it even more. I had a friend take a look at my code and he pointed that out and corrected it to what it currently is so we could get the solve.

Flag: `wctf{i_th1nk_y0u_m1sund3rst00d_h0w_r0t13_w0rk5}`