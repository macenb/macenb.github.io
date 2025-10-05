# Emoticonsole 2

A challenge from the US CyberGames Open CTF 2024

### Description

Files:
- [runtime.pyc](./runtime.pyc)
- [program.emo](./program.emo)

### Solve

This one had some trouble on the decompilation. I used the same tool as in Emoticonsole to decompile the `.pyc` file, but I had to look through the byte code manually for some of the later emoji definitions.

This file has a couple idiosyncracies that made it harder. First, it opens with an infinite loop, so i replaced that with the `nop` instruction included in the `pyc`. Second tricky thing was the xor values for the flag check were generated dynamically by some code at the beginning of the program. I made `runtime.py` based off of the byte code of `runtime.pyc` and used it to dynamically run through the program and check the xor values. 

I just broke on the comp function and compared the generated value and the value I inputted (`'a'`), then I wrote a function in the python terminal that took an input for each register and calculated what the value should be, added it to the flag, fixed the registers to be equal and continued. Did that all the way through.

```python
def solve(r0, r1):
    # input was just a bunch of a's and ord('a') == 97
    print(chr(r0 ^ 97 ^ r1))
```

Flag: `SIVUSCG{g3n_z_w0uld_b3_pr0ud}`