# Twisted

A challenge from the SAINTCON Hacker's Challenge 2024

### Description

This challenge will tell you when it's done. For inspiration, I recommend consulting the manual.

Files:
- [foo](./foo)
- [sofiles.zip](./sofiles.zip)

### Solve

This challenge was released really late, so I didn't have a lot of time to work through it. I started by looking at the decompilation.

Just on first glance, it was just one function, which made it easy to understand. The function was long, but only a little bit matters for us:

```c
__builtin_memset(&s, c: 0, n: 0x1c)
int64_t var_c28_1 = 0
var_a20.q = 0x1571
void* x5_1 = &var_a20:8

for (int64_t i = 1; i != 0x138; i += 1)
    int64_t x0_3 = *(x5_1 - 8)
    *x5_1 = i u% 0x138 + (x0_3 ^ x0_3 u>> 0x3e) * 0x5851f42d4c957f2d
    x5_1 += 8

int64_t var_60_1 = 0x138
char* var_c20
std::string::string<std::allocator<char> >(&var_c20, argv[1])
int64_t* var_c38_1
int32_t var_c30_1
int64_t var_c18

if (var_c18 != 0)
    int64_t x20_1 = 1
    int64_t x19_1 = 0
    int64_t x0_14
    
    do
        char x0_16 = std::mersenne_twister_en...l, 6364136223846793005ul>::operator()(&var_a20)
        int64_t x2_6 = x20_1 << 3
        uint32_t x0_19 = zx.d(var_c20[x19_1] ^ x0_16 ^ (*(x2_6 + &B_3 - 8)).b)
        uint32_t x4_1 = zx.d(*(x2_6 + &A_2 - 8))
        int64_t* x1_7 = var_c38_1

        if (x1_7 == var_c28_1)
            int64_t* var_c58_1 = x1_7
            std::vector<bool>::_M_insert_aux(&s, x1_7, var_c30_1.q, (x0_19 == x4_1 ? 1 : 0).b)
        else
            uint64_t x3_5 = zx.q(var_c30_1)
            
            if (x3_5.d == 0x3f)
                var_c30_1 = 0
                var_c38_1 = &x1_7[1]
            else
                var_c30_1 = x3_5.d + 1
            
            int64_t x2_10 = 1 << x3_5
            int64_t x0_12
            
            if (x0_19 != x4_1)
                x0_12 = *x1_7 & not.q(x2_10)
            else
                x0_12 = x2_10 | *x1_7
            
            *x1_7 = x0_12

```

Important takeaways:

- At the start of the function, you see a variable referred to as `var_a20` being assigned. This is the start of a MASSIVE buffer with fixed values. This is used in the number generation.
- `var_a20` (our fixed values) are used in the `mersenne_twister_en` function to generate pseudo-random values into `x0_16`
- Our input is used in the `std::string::string<std::allocator<char> >` statement and stored in `var_c20`
- Those values are passed in to generate `x0_19 = zx.d(var_c20[x19_1] ^ x0_16 ^ (*(x2_6 + &B_3 - 8)).b)`
- `x4_1` is generated from a fixed offset + a generated offset (`x2_6`): `zx.d(*(x2_6 + &A_2 - 8))`
- The variable `s` is used as a `std::vector<bool>`, which seems important. It is assigned based off `x0_19 == x4_1 ? 1 : 0`, where (as previously stated) `x0_19` is generated from the PRNG + our input and `x4_1` is our offset

From those takeaways, we can just walk through the binary and extract those values for the flag

Only problem:
```sh
└─$ file foo
foo: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=dcac4926ac695d125fe1c415642252519351cca1, for GNU/Linux 3.7.0, not stripped
```
it's an ARM binary, which doesn't run on my machine.

I've used this before, but qemu is really useful in this instance. There are a set of options that allow you to debug a binary of a different architecture (I've used it for MIPS rev before). 

Crash course in QEMU command line: 

First, we can run the binary with `qemu-aarch64`:
```sh
└─$ qemu-aarch64 foo
need argument
```

So we can add an argument. The memset for `s` is 0x1c, so that's probably the length of our string.
```sh
└─$ qemu-aarch64 foo AAAAAAAAAAAAAAAAAAAAAAAAAAAA
no
```

So it runs.

*Note*: the reason the .so files zip is in the attached files is so that you can have a runtime environment for the binary when it's within qemu. I just copied those into my `/lib` folder and then the binary had no issues.

Next step is to get debugging working. Qemu has the `-g` flag, which lets a binary be served on a specified port. Once it's served, you can connect in gdb-multiarch with the command `target remote` followed by a colon and the port number on your machine.

So in one terminal we run:
```sh
qemu-aarch64 -g 1234 foo AAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
And in the next terminal, we start gdb-multiarch on the file and run `target remote`:
```sh
$ gdb-multiarch -q foo
Poetry could not find a pyproject.toml file in /home/macen/ctfs/saintcon/hackerschallenge/twisted or its parents
pwndbg: loaded 169 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $bn_sym, $bn_var, $bn_eval, $ida GDB functions (can be used with print/break)
Reading symbols from foo...
(No debugging symbols found in foo)
------- tip of the day (disable with set show-tips off) -------
Want to NOP some instructions? Use patch <address> 'nop; nop; nop'
pwndbg> target remote :1234
```

And you'll see the binary hook in and start debugging. The only idiosyncracy is that you can't `run` the binary since it's already running. We can only `continue`.

I ran and stepped through until I got to where our input was being processed and I saw that my initial hypothesis was correct.

*Note*: I use `pwndbg`, which offers some really nice utilities for gdb, so my display may look different from what yours looks like

```
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────
*X0   0x496d191cf6f6aea6
*X1   0x41
*X2   8
*X3   0x93f555c238b0e7f8
*X4   0xb5026f5aa96619e9
*X5   0x7ff17e22bf18 ◂— 0x23b9c89211c7db80
*X6   0x7ff17e22bf20 ◂— 0x367692559aeadca8
*X7   4
*X8   0x7ff17d6f0ab0 —▸ 0x7ff17d3a22d0 ◂— 0
*X9   0x6d2f656d6f682f3d ('=/home/m')
 X10  0
 X11  0
*X12  0x7ff17d9e9160 —▸ 0x7ff17d740000 ◂— 0x3010102464c457f
*X13  0x3d
*X14  0x34e6b4
*X15  0x18
*X16  0x7ff17e24ef38 (memcpy@got[plt]) —▸ 0x7ff17d5e1c80 ◂— 0xaa0003e3d503201f
*X17  0x7ff17d5e1c80 ◂— 0xaa0003e3d503201f
*X18  6
 X19  0
*X20  1
*X21  0x7ff17e22ba40 ◂— 0x245b1c66f2bdc210
*X22  0x7ff17e22b950 ◂— 0x93f555c238b0e7f8
*X23  0x8000000000000000
*X24  0x7ff17e22b860 ◂— 0xda984cdece46493d
*X25  0x7ff17e22b818 ◂— 0
*X26  0x7ff17da2c000 (_rtld_global) —▸ 0x7ff17da2d350 —▸ 0x7ff17e22f000 ◂— 0x10102464c457f
*X27  0x7ff17e24ecf8 (__do_global_dtors_aux_fini_array_entry) —▸ 0x7ff17e22fd80 (__do_global_dtors_aux) ◂— stp x29, x30, [sp, #-0x20]!
 X28  0
*X29  0x7ff17e22c410 —▸ 0x7ff17e22c560 —▸ 0x7ff17e22c570 ◂— 0
*SP   0x7ff17e22b800 ◂— 4
 LR   0x7ff17e230034 (main+608) ◂— ldr x1, [sp, #0x40]
*PC   0x7ff17e23004c (main+632) ◂— eor x0, x0, x3
───────────────────────────────────────────────────[ DISASM / aarch64 / set emulate on ]────────────────────────────────────────────────────
 ► 0x7ff17e23004c <main+632>    eor    x0, x0, x3          X0 => 0xda984cdece46495e (0x496d191cf6f6aea6 ^ 0x93f555c238b0e7f8)
   0x7ff17e230050 <main+636>    eor    x1, x1, x0          X1 => 0xda984cdece46491f (0x41 ^ 0xda984cdece46495e)
   0x7ff17e230054 <main+640>    and    w0, w1, #0xff       W0 => 31 (0xce46491f & 0xff)
   0x7ff17e230058 <main+644>    add    x2, x2, x24         X2 => 0x7ff17e22b868 (0x8 + 0x7ff17e22b860)
   0x7ff17e23005c <main+648>    ldurb  w4, [x2, #-8]       W4, [0x7ff17e22b860] => 0x3d
   0x7ff17e230060 <main+652>    ldr    x1, [sp, #0x28]     X1, [0x7ff17e22b828] => 0
   0x7ff17e230064 <main+656>    ldr    x2, [sp, #0x38]     X2, [0x7ff17e22b838] => 0
   0x7ff17e230068 <main+660>    cmp    x1, x2              0 - 0     CPSR => 0x60000000 [ n Z C v q pan il d a i f el:0 sp ]
   0x7ff17e23006c <main+664>  ✔ b.eq   #main+716                   <main+716>
    ↓
   0x7ff17e2300a0 <main+716>    str    x1, [sp, #8]        [0x7ff17e22b808] <= 0
   0x7ff17e2300a4 <main+720>    ldr    w2, [sp, #0x30]     W2, [0x7ff17e22b830] => 0
─────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────
00:0000│ sp  0x7ff17e22b800 ◂— 4
01:0008│     0x7ff17e22b808 ◂— 0x66474e551
02:0010│     0x7ff17e22b810 ◂— 0
... ↓        5 skipped
───────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────
 ► 0   0x7ff17e23004c main+632
   1   0x7ff17d5684c4 None
   2   0x7ff17d568598 __libc_start_main+152
   3   0x7ff17e22fcf0 _start+48
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

As you can see, our input is in `X1`, there's an XOR operation at `main+636` that takes that input and something else (probably the output of Mersenne), and then there's a cmp between that and `X2`. And the value stored in `X2` is pulled from `[x24]-8`. It's actually displayed in our `pwndbg` and is `0x3d`. Just as a test, let's see what our low byte of `X0` xor `0x3d` is:

```python
>>> print(chr(0x3d^0x5e))
c
```

So it's printable! And `c` is a really likely candidate for our flag character.

I got the full solve for this challenge by breaking at `main+632`, continuing, grabbing those values, then continuing again and grabbing the next values until execution ended to get the full solve.

Original solve script:
```python
flag = [0x5e^0x3d, 0x9b^0xb0, 0x2e^5, 0x59^0x79, 0x9b^0xa2, 0x9d^0xaf, 0x94^0xa4, 0x99^0xee,0x96^0xa3,0xc0^0xe0,0x99^0xa9,0xa9^0xc7,0x36^0x16,0x6e^0x17,0xb0^0x80,0x8d^0xf8,0xe5^0xc5,0x45^0x74,0xd8^0xe9,0xf0^0x9b,0x20^0x13,0xec^0xcc,0x2e^0x1a,0xc3^0xe3,0xb9^0xdf,0x5f^0x2a,0x7b^0x15,0x86^0xbf,0xc1^0xb4,0x17^0x22]
print(''.join([chr(i) for i in flag]))
```

Flag: `c++ 920w5 0n y0u 11k3 4 fun9u5`

After the fact, I decided to figure out how to script this in Python. I've seen the `gdb` library used before, but I had never used it myself. Turns out, you can make a subclass to a Breakpoint in `gdb` and overwrite the `stop()` functionality to do custom things. 

I also used `gdb.events.exited.connect` to run a custom function when gdb exits the executable (when it finishes running)

My script is below, and I'll leave it up to you to figure out exactly how it works. You just open up gdb-multiarch in the same was, `target remote` in, and then run `source gdbsolve.py` and it runs and prints the flag. This was a really neat project and I learned a lot from it.

```python
import gdb

flag = []
hits = 0

class BreakpointHandler(gdb.Breakpoint):
    def __init__(self,location):
        super(BreakpointHandler, self).__init__(location)
        self.silent = True
    
    def stop(self):
        global hits # fun fact, to modify a global variable in a function, you need to declare it as global

        # Get the value in register x0
        x0_value = gdb.selected_frame().read_register('x0')
        x0 = x0_value&0xff

        # Get the address in register x24 and dereference it
        x24_address = gdb.parse_and_eval('$x24') + hits*8
        value_at_x24 = gdb.parse_and_eval(f'*({x24_address})')  # Dereference x24
        x24=value_at_x24&0xff
        flag.append(bytes([x0^x24]))
        hits += 1
        return False

def on_exit(event):
    print(b''.join(flag))


BreakpointHandler("*main+636")
gdb.events.exited.connect(on_exit)
gdb.execute("continue")
```