## Debugalyzer

This challenge was a part of DiceCTF 2025 (the qualifiers). I was playing with [Monosodium Glutamate; Or, the Best Team](https://ctftime.org/team/379366) for this CTF, and we got 80th overall and 8th in the US Undergrad division.

### Description

Stripped rev is too hard - I've added even more debuginfo to help you with this challenge!

Files:
- [debugalyzer.zip](./debugalyzer.zip)

### Solve

This challenge was also attached to `debugapwner` in the pwn category, so I started poking around with it there before I had the main file. This gave me a lot of familiarity with the code before I had even started to go through the reversing of the main binary attached to the challenge.

Two files were given: `dwarf` and `main`. The `dwarf` file had the actual parser, and was the only file given for the pwn challenge, so I spent a long time reversing it before I had the actual main file. The main function starts as follows:

```c
void* fsbase
int64_t rax = *(fsbase + 0x28)
setbuf(fp: __bss_start, buf: nullptr)
int32_t result

if (argc s<= 1)
    fprintf(stream: stderr, format: "Usage: %s <elf-file>\n", *argv)
    result = 1
else if (elf_version(1) == 0)
    fwrite(buf: "ELF library initialization faile…", size: 1, count: 0x22, fp: stderr)
    result = 1
else
    int32_t fd = open(file: argv[1], oflag: 0)
    
    if (fd s< 0)
        perror(s: "open")
```

It's using the `libelf.h` library, which I installed to play around with. This is something like the C code for this file might look like:
```c
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed\n");
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin failed\n");
        close(fd);
        return 1;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx failed\n");
        elf_end(elf);
        close(fd);
        return 1;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) continue;

        char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (strcmp(name, ".debug_line") == 0) {
            printf("Section: %s\n", name);

            Elf_Data *data = elf_getdata(scn, NULL);
            if (data == NULL || data->d_buf == NULL) {
                continue;  // Skip if no data is available for this section
            }

            // Here you can process the data as needed, for example:
            int64_t *header_data = (int64_t *)data->d_buf;
            if (header_data != NULL) {
                // You can access the data in the header
                printf("Header data: 0x%lx, 0x%lx\n", header_data[0], header_data[1]);

                // Further processing if required
                // Example: If the 3rd element in the header is used in your code
                int64_t rax_8 = header_data[2];
                printf("Third element (rax_8): 0x%lx\n", rax_8);
            }

        }
    }

    elf_end(elf);
    close(fd);
    return 0;
}
```

It loads the elf file and reads it to the point where it finds the section `.debug_line`. It was a lot of fun implementing this code and learning about the ELF format and parsing ELF files with C, but it wasn't at all relevant to the challenge. This debug section stores dwarf bytecode that defines debug information for the file. Typically you could compile this debug information in with the `-g` flag in `gcc`, and it will call the dwarf bytecode to read information about the original C file when you open it in gdb. In our case, that bytecode is actually run through the `execute_dwarf_bytecode_v4` function, which contains the interesting components to reverse.

This function looks as follows (in Binary ninja):
```c
int64_t execute_dwarf_bytecode_v4(void* in_data, int64_t ins_len, void* scn, int64_t line_base, char idek)
    void* data_stream = in_data
    int64_t current_data_length = ins_len
    int32_t flag_correct_0
    
    if (ins_len == 0)
        flag_correct_0 = 1
    else
        int64_t i = ins_len
        flag_correct_0 = 1
        
        do
            void* data_stream_3 = data_stream
            char parsed_flag_chars = *data_stream_3
            void* data_stream_4 = data_stream_3 + 1
            data_stream = data_stream_4
            int64_t data_len = i - 1
            current_data_length = data_len
            
            if (parsed_flag_chars == 0)  // extended opcode
                int64_t rax_1 = read_uleb128(&data_stream, &current_data_length)
                int64_t current_data_length_4 = current_data_length
                
                if (current_data_length_4 == 0)
                    break
                
                void* data_stream_5 = data_stream
                char opcode = *data_stream_5
                data_stream = data_stream_5 + 1
                int64_t current_data_length_3 = current_data_length_4 - 1
                current_data_length = current_data_length_3
                
                if (opcode == 0x51)
                    int32_t offset = read_uleb128(&data_stream, &current_data_length)
                    int64_t current_data_length_1 = current_data_length
                    
                    if (current_data_length_1 == 0)
                        break
                    
                    void* data_stream_1 = data_stream
                    char rsi_3 = *data_stream_1
                    data_stream = data_stream_1 + 1
                    current_data_length = current_data_length_1 - 1
                    *(&flag + sx.q(offset)) = rsi_3
                else if (opcode u> 0x51)
                    // greater than 0x52 is "check flag"
                    if (opcode != 0x52)
                        label_15af:
                        printf(format: "Extended opcode %d unimplemented…", 0)
                        
                        if (rax_1 u> 1)
                            while (true)
                                if (current_data_length_3 == 0)
                                    // returns true on var_50==0
                                    return puts(str: select_str("Flag is incorrect!", "Flag is correct!", flag_correct_0.b))
                                
                                if (current_data_length_3 - 1 == current_data_length_4 - rax_1)
                                    break
                                
                                current_data_length_3 -= 1
                            
                            current_data_length = current_data_length_3 - 1
                            data_stream = data_stream_5 + 1 + current_data_length_4 - current_data_length_3
                    else
                        int32_t flag_ind_1 = read_uleb128(&data_stream, &current_data_length)
                        
                        if (current_data_length == 0)
                            break
                        
                        char flag_char_1 = *(&flag + sx.q(flag_ind_1))
                        int32_t flag_ind_2 = read_uleb128(&data_stream, &current_data_length)
                        int64_t current_data_length_2 = current_data_length
                        
                        if (current_data_length_2 == 0)
                            break
                        
                        char flag_char_2 = *(&flag + sx.q(flag_ind_2))
                        void* data_stream_2 = data_stream
                        char rdi_8 = *data_stream_2
                        current_data_length = current_data_length_2 - 1
                        
                        if (current_data_length_2 == 1)
                            break
                        
                        if (rdi_8 == 2)
                            parsed_flag_chars = flag_char_1 * flag_char_2
                        else if (rdi_8 u<= 2)
                            parsed_flag_chars = flag_char_1 - flag_char_2
                            
                            if (rdi_8 == 0)
                                parsed_flag_chars = flag_char_2 + flag_char_1
                        else if (rdi_8 == 3)
                            parsed_flag_chars = flag_char_2 ^ flag_char_1
                        
                        data_stream = data_stream_2 + 2
                        current_data_length = current_data_length_2 - 2
                        void* cur_len=2
                        cur_len=2.b = current_data_length_2 != 2
                        int64_t rdx_2
                        rdx_2.b = parsed_flag_chars != *(data_stream_2 + 1)
                        // THIS MATTERS
                        flag_correct_0 &= (cur_len=2.d & rdx_2.d) ^ 1
                else if (opcode != 1)
                    if (opcode != 2)
                        goto label_15af
                    
                    if (rax_1 u>= zx.q(idek) + 1)
                        uint64_t idek_1 = zx.q(idek)
                        uint64_t idek_2
                        
                        if (idek_1 == 0)
                            idek_2 = idek_1
                        else
                            idek_2 = 0
                            
                            do
                                idek_2 += 1
                            while (idek_1 != idek_2)
                        
                        data_stream = data_stream_5 + 1 + idek_2
                        current_data_length = current_data_length_3 - idek_2
            else if (parsed_flag_chars u< *(scn + 3))
                switch (parsed_flag_chars)
                    case 1, 6, 7, 8, 0xa, 0xb
                        nop
                    case 2
                        read_uleb128(&data_stream, &current_data_length)
                    case 3
                        do
                            char rax_17 = *data_stream_4
                            data_stream_4 += 1
                            data_len -= 1
                            
                            if (rax_17 s>= 0)
                                break
                        while (data_len != 0)
                        
                        data_stream = data_stream_4
                        current_data_length = data_len
                    case 4
                        read_uleb128(&data_stream, &current_data_length)
                    case 5
                        read_uleb128(&data_stream, &current_data_length)
                    case 9
                        if (data_len u> 1)
                            data_stream = data_stream_3 + 3
                            current_data_length = i - 3
                    case 0xc
                        read_uleb128(&data_stream, &current_data_length)
                    default
                        printf(format: "Opcode %d unimplemented\n", zx.q(parsed_flag_chars))
            
            i = current_data_length
        while (i != 0)
    
    return puts(str: select_str("Flag is incorrect!", "Flag is correct!", flag_correct_0.b))
```

This is a *big* function, and it has a lot of checks. The main components of dwarf bytecode are defined [here](https://wiki.osdev.org/DWARF). There are only a few defined opcodes, which are all covered at the bottom of the C program. The piece we care about is the flag, which is defined as a global variable called `flag`. This is only affected by two opcodes, 0x51 and 0x52 (81 and 82). This, then, is likely the focus of our reversing of the dwarf bytecode in the main file.

The main file contains debug information in it's debugline, which you can list out with `objdump --dwarf=rawline ./source/main`. This prints a lot of information that helps us, especially when identifying the uses of those two opcodes:
```
./source/main:     file format elf64-x86-64

Raw dump of debug contents of section .debug_line:

  Offset:                      0
  Length:                      1686
  DWARF Version:               4
  Prologue Length:             54
  Minimum Instruction Length:  1
  Maximum Ops per Instruction: 1
  Initial value of 'is_stmt':  1
  Line Base:                   -5
  Line Range:                  14
  Opcode Base:                 13

 Opcodes:
  Opcode 1 has 0 args
  Opcode 2 has 1 arg
  Opcode 3 has 1 arg
  Opcode 4 has 1 arg
  Opcode 5 has 1 arg
  Opcode 6 has 0 args
  Opcode 7 has 0 args
  Opcode 8 has 0 args
  Opcode 9 has 1 arg
  Opcode 10 has 0 args
  Opcode 11 has 0 args
  Opcode 12 has 1 arg

 The Directory Table (offset 0x1c):
  1     /usr/include

 The File Name Table (offset 0x2a):
  Entry Dir     Time    Size    Name
  1     0       0       0       main.c
  2     1       0       0       stdio.h

 Line Number Statements:
  [0x00000040]  Set column to 12
  [0x00000042]  Extended opcode 2: set Address to 0x1139
  [0x0000004d]  Special opcode 7: advance Address by 0 to 0x1139 and Line by 2 to 3
  [0x0000004e]  Set column to 5
  [0x00000050]  Special opcode 62: advance Address by 4 to 0x113d and Line by 1 to 4
  [0x00000051]  Set column to 1
  [0x00000053]  Advance PC by constant 17 to 0x114e
  [0x00000054]  Special opcode 48: advance Address by 3 to 0x1151 and Line by 1 to 5
  [0x00000055]  Advance PC by 2 to 0x1153
  [0x00000057]  Extended opcode 81: UNKNOWN: length 2 [ 00 64]
  [0x0000005c]  Extended opcode 81: UNKNOWN: length 2 [ 01 69]
  [0x00000061]  Extended opcode 81: UNKNOWN: length 2 [ 02 63]
  [0x00000066]  Extended opcode 81: UNKNOWN: length 2 [ 03 65]
  [0x0000006b]  Extended opcode 81: UNKNOWN: length 2 [ 04 7b]
  [0x00000070]  Extended opcode 81: UNKNOWN: length 2 [ 05 58]
  [0x00000075]  Extended opcode 81: UNKNOWN: length 2 [ 06 58]
  .... [Excluded for brevity] ....
  [0x00000110]  Extended opcode 81: UNKNOWN: length 2 [ 25 58]
  [0x00000115]  Extended opcode 81: UNKNOWN: length 2 [ 26 58]
  [0x0000011a]  Extended opcode 81: UNKNOWN: length 2 [ 27 7d]
  [0x0000011f]  Extended opcode 82: UNKNOWN: length 4 [ 00 13 01 f7]
  [0x00000126]  Extended opcode 82: UNKNOWN: length 4 [ 00 17 01 30]
  [0x0000012d]  Extended opcode 82: UNKNOWN: length 4 [ 00 1c 03 13]
  [0x00000134]  Extended opcode 82: UNKNOWN: length 4 [ 00 16 00 95]
  .... [Excluded for brevity] ....
  [0x00000689]  Extended opcode 82: UNKNOWN: length 4 [ 27 1e 00 ef]
  [0x00000690]  Extended opcode 82: UNKNOWN: length 4 [ 27 24 01 0a]
  [0x00000697]  Extended opcode 1: End of Sequence
```

The are a lot of 81 and 82, which means this is the right track to follow. The first opcode, 81, could be renamed `store_char`, since it stores a character in the flag object. Then, opcode 82 could be renamed to `check_chars`. It takes two characters from the flag, an operation marker, and an expected result, and it returns true or false depending on `flag_char_1 operation flag_char_2 == result`. We have a few characters given by the inserted flag: `dice{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}`. Obviously, all of the X's are wrong, but `dice{` is correct. The format that the bytecode 0x52 takes as input is 4 bytes: `index_1 index_2 operation result`. For example, the first occurence of 0x52 takes these arguments: `00 13 01 f7`.

Note: the operations are tied as follows: `{ 0: +, 1: -, 2: *, 3, ^}`.

Those arguments for the opcode are parsed as follows, according to the specified format: `flag[arg[0]] - flag[arg[1]] == flag[arg[3]]`. During the CTF, I solved this by just using the debugger, but looking at it now, it seems like a really easy and optimal solve to run through `z3`... so I spent 10 minutes just now and wrote the solve that took me an hour and a half to do manually...

```c
debug = ["00 13 01 f7", "00 17 01 30", "00 1c 03 13", "00 16 00 95", "00 24 03 17", "01 19 01 f5", "01 25 03 5a", "01 0f 00 cc", "01 16 03 58", "01 1e 00 db", "02 10 02 bd", "02 0a 02 cb", "02 1b 01 ff", "02 20 00 c2", "02 18 03 0d", "03 1f 02 3e", "03 1b 00 c9", "03 0b 02 7b", "03 06 00 96", "03 15 02 9c", "04 11 02 91", "04 05 01 13", "04 23 00 ed", "04 24 03 08", "04 08 02 f8", "05 08 00 d0", "05 1a 01 09", "05 15 01 fc", "05 0e 02 b8", "05 24 00 db", "06 00 02 24", "06 18 00 9f", "06 22 00 65", "06 15 01 c5", "06 0d 03 41", "07 17 00 9b", "07 01 01 fe", "07 26 03 15", "07 10 00 c6", "07 1e 03 15", "08 00 03 0c", "08 26 00 da", "08 1b 03 0c", "08 17 01 34", "08 09 01 fc", "09 09 01 00", "09 23 03 1e", "09 19 01 f8", "09 22 03 58", "09 20 01 0d", "0a 16 01 48", "0a 08 01 11", "0a 19 03 0d", "0a 0e 01 46", "0a 1d 01 45", "0b 00 03 3b", "0b 20 00 be", "0b 13 00 cc", "0b 23 00 d1", "0b 0e 02 ed", "0c 0d 00 e3", "0c 0b 01 14", "0c 19 01 ff", "0c 14 00 e3", "0c 06 03 42", "0d 24 03 03", "0d 05 03 18", "0d 02 03 13", "0d 06 01 3f", "0d 26 00 e2", "0e 06 01 02", "0e 16 00 64", "0e 24 03 40", "0e 0d 01 c3", "0e 0c 01 c0", "0f 1c 03 14", "0f 0d 01 f3", "0f 14 03 13", "0f 22 01 2f", "0f 15 02 c4", "10 11 01 fc", "10 17 01 2b", "10 25 00 92", "10 14 00 cf", "10 05 01 f7", "11 23 03 11", "11 1d 02 1c", "11 02 02 49", "11 10 00 c2", "11 0a 01 ea", "12 16 01 ff", "12 27 02 70", "12 14 03 40", "12 15 03 5c", "12 23 01 be", "13 26 00 df", "13 23 01 fb", "13 0f 01 0a", "13 12 00 9d", "13 1e 01 fb", "14 07 01 09", "14 01 00 d9", "14 11 03 13", "14 27 03 0d", "14 10 01 11", "15 08 01 04", "15 01 03 05", "15 17 01 38", "15 03 01 07", "15 1e 03 1e", "16 1b 03 55", "16 08 01 c9", "16 17 03 05", "16 27 00 ae", "16 12 00 61", "17 00 02 50", "17 18 00 a2", "17 26 03 46", "17 22 02 90", "17 25 02 5c", "18 06 03 5f", "18 01 01 05", "18 23 00 e0", "18 03 01 09", "18 0b 03 31", "19 1c 03 03", "19 1e 00 e6", "19 06 00 a5", "19 03 03 11", "19 08 03 1c", "1a 0a 00 d8", "1a 1f 02 da", "1a 23 00 d1", "1a 0d 00 cf", "1a 17 00 93", "1b 07 00 cb", "1b 14 02 c0", "1b 06 00 95", "1b 1e 00 d6", "1b 22 02 50", "1c 1f 03 11", "1c 0d 00 e7", "1c 1e 01 05", "1c 27 03 0a", "1c 05 03 1f", "1d 27 00 b1", "1d 20 03 6b", "1d 0f 02 1c", "1d 18 00 a2", "1d 1c 02 2c", "1e 18 02 fc", "1e 24 02 36", "1e 1b 02 88", "1e 0e 02 b6", "1e 1e 01 00", "1f 12 02 20", "1f 21 03 16", "1f 07 00 cd", "1f 1d 00 9a", "1f 04 00 e1", "20 22 03 6b", "20 23 00 d1", "20 02 02 bd", "20 20 03 00", "20 12 02 d0", "21 13 01 03", "21 0c 01 fd", "21 19 03 04", "21 10 03 2f", "21 1e 00 e2", "22 07 02 ec", "22 0a 02 94", "22 02 00 97", "22 1e 02 28", "22 0f 02 1c", "23 08 01 0a", "23 10 00 d1", "23 1f 03 14", "23 09 01 06", "23 21 03 02", "24 0f 00 d6", "24 27 00 f0", "24 0a 00 ec", "24 23 03 01", "24 04 01 f8", "25 11 00 96", "25 08 03 5b", "25 17 00 67", "25 24 01 c0", "25 07 02 85", "26 0d 01 02", "26 1f 03 14", "26 27 02 aa", "26 0c 01 ff", "26 1c 02 fe", "27 16 00 ae", "27 18 03 13", "27 02 01 1a", "27 1e 00 ef", "27 24 01 0a"] 

from z3 import *

# Define unknown variable
vec = [BitVec(f'v{i}', 8) for i in range(0x28)]

# Create solver
solver = Solver()

def process_input(inputs):
    inputs = [int(i, 16) for i in inputs.split()]
    if inputs[2] == 0:
        return (vec[inputs[0]] + vec[inputs[1]])&0xff == inputs[3]
    if inputs[2] == 1:
        return (vec[inputs[0]] - vec[inputs[1]])&0xff == inputs[3]
    if inputs[2] == 2:
        return (vec[inputs[0]] * vec[inputs[1]])&0xff == inputs[3]
    if inputs[2] == 3:
        return vec[inputs[0]] ^ vec[inputs[1]] == inputs[3]

solver.add(vec[0] == ord('d'))
solver.add(vec[1] == ord('i'))
solver.add(vec[2] == ord('c'))
solver.add(vec[3] == ord('e'))
solver.add(vec[4] == ord('{'))
for arg in debug:
    solver.add(process_input(arg))

# Solve
if solver.check() == sat:
    model = solver.model()
    chars = [chr(model[v].as_long()) for v in vec]
    print(''.join(chars))
else:
    print("No solution exists.")
```

This does all of the parsing that I just described and just... sovles it for me. I've copied the base of this into a z3 template for future challenges like this. When you run this, it just prints out the flag! I pulled all of the conditions in `debug` with find and replace on the output of the `objdump`.

Flag: `dice{h1ghly_sp3c_c0mpl14nt_dw4rf_p4rs3r}`
