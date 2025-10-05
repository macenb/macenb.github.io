# Unravel

A challenge from the US CyberGames Open CTF 2024

### Description

Files:
- [unravel_exploit.pcap](./unravel_exploit.pcap)

### Solve

This challenge said you just needed to find the `unravel{...}` formatted flag in the pcap and submit it to the website they linked you to. However, when you go find the flag in the file, you learn that the flag changes every once in a while and is now out of date.

The solve, then, is recreating the whole exploit from the packets in the pcap file. The solve walks through every piece of the exploit. The trickiest part was realizing that the key was not in fact hex encoded, but a 16 byte key in and of itself.

Solve: [solve.py](./solve.py)

Flag: `SIVUSCG{r3vers3_att@cks_c@sh_ch3cks}`