import random

correct = [192, 123, 40, 205, 152, 229, 188, 64, 42, 166, 126, 125, 13, 187, 91]

for time in range(1704006000, 1704006000+86400+86400):
    # if time % 1000 == 0:
    #     print(time)

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