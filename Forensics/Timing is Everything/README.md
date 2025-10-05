# Timing is Everything

A challenge from the US CyberGames Open CTF 2024

### Description

Files:
- [timingiseverything.pcap](./timingiseverything.pcap)

### Solve

When you open the pcap file, you can just see 30 ICMP packets that are fairly normal. Following the hint given by the challenge description, you can get the flag by pulling the time values from each packet, normalizing away major jumps, and taking chr(t(i+1) - t(i)) for each packet i.

Solve: [solve.py](./timing_solve.py)

Flag: `SIVUSCG{T1m1n9_15_3v3ryth1n9}`