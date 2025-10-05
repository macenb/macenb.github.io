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

"""
this works, which is really cool
just run qemu-aarch64 in one window and gdb-multiarch in another, then target remote in and source the script
then it'll just run

Interesting facts:
it has a weird time grabbing hex from registers, but you can and some bits to get the right value (i.e. hex negative lol)
return false tells gdb that the breakpoint was a false alarm and the program should continue
the breakpoint class overwrite basically is a really neat way to customize breakpoint behavior in gdb, especially stop()
"""