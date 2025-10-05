# Emoticonsole

A challenge from the US CyberGames Open CTF 2024

### Description

Files:
- [runtime.pyc](./runtime.pyc)
- [program.emo](./program.emo)

### Solve

When you reverse the `.pyc` file using an online decompiler (I've used [this one](https://www.lddgo.net/en/string/pyc-compile-decompile) in the past, but it didn't support Python 3.11 so I had to migrate to [this one](https://pylingual.io/)), it returns the file [runtime.py](./runtime.py). When looking through it, you can see that it uses a set of basic functions denoted by various emojis.

From here, I solved it by reversing program.emo statically. It prints each character of the check statement first, then takes inputs, checks them against an xor, and exits if it fails. I'd recommend running through that thought process yourself, mostly because its fun and it would be annoying to explain in this write up.

Flag: `SIVUSCG{em0t1on4l_d4m4g3}`