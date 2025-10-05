# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: ./runtime.py
# Bytecode version: 3.11a7e (3495)
# Source timestamp: 2024-06-02 06:03:02 UTC (1717308182)

import sys

class EmptyStackException(Exception):
    """Raised when the program tries to pop an empty stack"""

class InvalidInstructionException(Exception):
    """Raised when the program encounters an invalid emoji"""

class EmoProgram:

    def __init__(self, F):
        self.P = []
        i = 0
        while i < len(F):
            I = F[i]
            if I == '🔼':
                self.P.append(F[i:i + 4])
                i += 4
            elif I == '🔄' or I == '🔁':
                self.P.append(F[i:i + 4])
                i += 4
            else:
                self.P.append(I)
                i += 1
        self.STACK = []
        self.PC = 0
        self.NUMS = {'⓿': '0', '⓵': '1', '⓶': '2', '⓷': '3', '⓸': '4', '⓹': '5', '⓺': '6', '⓻': '7', '⓼': '8', '⓽': '9'}
        self.EMO = {'🌞': self.emo_func_start, '📥': self.emo_func_input_byte, '🔼': self.emo_func_push_byte, '⊕': self.emo_func_xor_byte, '❔': self.emo_func_jump_if, '🟰': self.emo_func_compare, '🔄': self.emo_func_jump_back, '🔁': self.emo_func_jump_forward, '➖': self.emo_func_subtract, '➕': self.emo_func_add, '🔊': self.emo_func_output_byte, '🌛': self.emo_func_exit}

    def emo_func_start(self, I):
        return

    def emo_func_input_byte(self, I):
        V = ord(sys.stdin.read(1))
        self.STACK.append(V)

    def emo_func_push_byte(self, I):
        X = int(''.join([self.NUMS[I[i]] for i in range(1, 4)]))
        self.STACK.append(X)

    def emo_func_xor_byte(self, I):
        if len(self.STACK) > 1:
            V1 = self.STACK.pop()
            V2 = self.STACK.pop()
            self.STACK.append(V1 ^ V2)
        else:
            raise EmptyStackException

    def emo_func_compare(self, I):
        if len(self.STACK) > 1:
            V1 = self.STACK.pop()
            V2 = self.STACK.pop()
            if V1 == V2:
                self.STACK.append(1)
            else:
                self.STACK.append(0)
        else:
            raise EmptyStackException

    def emo_func_jump_if(self, I):
        if len(self.STACK) > 0:
            C = self.STACK.pop()
            if C == 1:
                self.PC += 1
        else:
            raise EmptyStackException

    def emo_func_jump_back(self, I):
        self.emo_func_push_byte()
        V = self.STACK.pop()
        PC -= V
        F.seek(PC)

    def emo_func_jump_forward(self, I):
        self.emo_func_push_byte()
        V = self.STACK.pop()
        PC += V
        F.seek(PC)

    def emo_func_subtract(self, I):
        if len(self.STACK) > 1:
            V1 = self.STACK.pop()
            V2 = self.STACK.pop()
            self.STACK.append(V1 - V2)
        else:
            raise EmptyStackException

    def emo_func_add(self, I):
        if len(self.STACK) > 1:
            V1 = self.STACK.pop()
            V2 = self.STACK.pop()
            self.STACK.append(V1 + V2)
        else:
            raise EmptyStackException

    def emo_func_output_byte(self, I):
        if len(self.STACK) > 0:
            V = self.STACK.pop()
            sys.stdout.write(chr(V))
        else:
            raise EmptyStackException

    def emo_func_exit(self, I):
        sys.exit(0)

    def run_program(self):
        self.PC = 0
        while True:
            I = self.P[self.PC]
            fn = self.EMO.get(I[0], None)
            if fn is not None:
                fn(I)
                self.PC += 1
            else:
                print(I[0])
                print('Invalid instruction encountered.')
                sys.exit(1)
if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('Usage: ./runtime input_file.emo')
        sys.exit(1)
    try:
        F = open(sys.argv[1], 'r').read()
        program = EmoProgram(F)
        program.run_program()
    except FileNotFoundError:
        print('Unable to open input file.')