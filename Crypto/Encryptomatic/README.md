# Encryptomatic

A challenge from the US CyberGames Open CTF 2024

### Description

Files:
- [main.py](./main.py)

### Solve

This challenge was a really simple ECB encryption oracle. The general concept is that because encryption of each block is standard and the flag is appended to your input, you can create blocks that only have one unknown character. Once you have that, you can then brute force other blocks to find that character, and then continue forward. Cryptopals has a really nice example of this challenge, as might Cryptohack.

Solve: [solve.py](./solve.py)

Flag: `SIVUSCG{3CB_sl1d3_t0_th3_l3ft}`