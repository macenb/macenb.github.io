# forensics / wreck

A challenge from Buckeye CTF 2024

### Description

I hate when my ship crashes

File: `dump`

### Solve

I've never worked with core dumps before, but a couple random write ups said to throw it into gdb, so I did. I just ran `gdb` and `core dump` since the file was named dump it made it very coincidentally plaintext lol. This output said it was a dump from a Python file called `wreck.py`. The gdb output also showed various dependencies that were in the core dump that were unmet by my environment, and one of those was Python pillow, which I'm familiar with as an image processing library. I figured the solve was to extract an image from the dump.

To start, I ran binwalk and looked through its output until I found a JPEG. Since `-e` didn't extract it, I had to do it manually with dd.

```sh
dd if=dump of=dump1.jpg bs=1 skip=2108736 count=25986
```

That returned an image that had the flag: `bctf{D4MN_7h47_c0r3_dvmp_907_4_GY477}`