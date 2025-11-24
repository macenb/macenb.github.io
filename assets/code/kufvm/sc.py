import subprocess, string

def count_instructions(flag_guess: str):
    cmd = "taskset -c 0 perf stat -x, -e cpu_core/instructions/u -- ./main chall.bin".split()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
        # text=True
    )
    out, err = proc.communicate(flag_guess.encode() + b'\n')
    # perf sends statistics to stderr

    # this made it work, still not sure why the last iteration ran into trouble
    if out.split(b':')[-1].strip() != b'incorrect!':
        return 10000000000000  # program quit, invalid flag
    
    insns = int(err.decode().split(',')[0])
    return insns

flag = ''
while len(flag) == 0 or flag[-1] != '}':
    counts = []
    for i in string.printable:
        counts.append((i, count_instructions(flag + i)))
        # print(f'Tried {flag + i}: {counts[-1][1]} instructions')
    best_candidate = sorted(counts, key=lambda x: x[1], reverse=True)[0]
    flag += best_candidate[0]
    print(f'Best candidate so far: {flag}')
# this worked like a charm MINUS the '}' which it didn't find... not sure why
# sknb{This_is_rev_flag!_congrats!!!!_167a14}