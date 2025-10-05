# Limited 2

A challenge from WolvCTF 2024

### Description:

I was AFK when the flag was being encrypted, can you help me get it back?

Files:
- [NY_chal_time.py](./NY_chal_time.py)

### Solve:

So this challenge is obviously a seed-based random generation challenge. Once we find the secret timestamp used to seed the number generator, we can find the original flag! The code gives us some hints on what the time could be:

```python
if time.gmtime().tm_year >= 2024 or time.gmtime().tm_year < 2023:
    print('Nope :(')
    sys.exit(1)
if time.gmtime().tm_yday != 365 and time.gmtime().tm_yday != 366:
    print('Nope :(')
    sys.exit(1)
```

So the first is that the year MUST be 2023, and the second is that the day must be either 365 or 366 (the last day of the year or the first of the next, since it wasn't a leap year). Hence the NY in the file name, we're working with the change into the new year. The timestamp of the start of Dec 31, 2023 is 1704006000, so we just need to work from there up two days. The one tricky thing is that it waits and then re-seeds based on how long it waited, but since we know the seed we can also guess that and just add to the original timestamp instead of waiting the time (making the brute force more efficient).

Here is the solve script!

```python
import random

correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]

for time in range(1704006000, 1704006000+86400+86400):

    flag = []
    sleep = 0
    for i in range(len(correct)):
        random.seed(i+time+sleep)
        flag.append(correct[i] ^ random.getrandbits(8))
        sleep += random.randint(1, 60)

    flag_str = ''.join([chr(c) for c in flag])

    if 'wctf' in flag_str:
        print(flag_str)
        print(time)
```

As it turns out, the timestamp of the solve was 1704153599 and we found the flag!

Flag: `wctf{b4ll_dr0p}`