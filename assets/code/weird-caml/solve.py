from z3 import *
import re
from Crypto.Util.number import long_to_bytes

solver = Solver()

PROGRAM = ''

with open('main.ml', 'r') as f:
    ocaml_source = f.read()

vars = re.findall(r"'([a-zA-Z0-9_]+) val_t \*", ocaml_source)
bool_inits = [(f"{v} = Bool('{v}')", v) for v in vars] # gathers all the bools from the main Puzzle type

PROGRAM += '\n'.join([i[0] for i in bool_inits])
variable_names = [v[1] for v in bool_inits]
PROGRAM += '\n\n'

type_blocks = re.findall(
    r"type\s*\(\s*([^)]+)\s*\)\s*(\w+)\s*=", ocaml_source)

for params, typename in type_blocks:
    params_list = [p.strip().lstrip("'") for p in params.split(',')]

    function_definition = f"def {typename}({', '.join(params_list)}):\n    return Or(\n"

    type_cons = re.findall(fr"-> \(([^)]+)\)\s+{typename}", ocaml_source)
    for t in type_cons:
        parts = [p.strip() for p in t.split(",")]
        indices = [f"        {params_list[i]} == {val.lstrip('b_').capitalize()},\n" for i, val in enumerate(parts) if val in ("b_true", "b_false")]
        for x in indices:
            function_definition += x
    function_definition += '    )\n\n'
    PROGRAM += function_definition

PROGRAM += "# conditions\n\n"

matches = re.findall(r"    \(\s*([^)]+)\s*\)\s*(\w+)_t", ocaml_source)

for params_str, typename in matches:
    params = [p.strip().lstrip("'") for p in params_str.split(",")]
    call_str = f"solver.add({typename}_t({', '.join(params)}))\n"
    PROGRAM += call_str

with open('model.py', 'w') as f2:
    f2.write(PROGRAM)    

exec(PROGRAM, globals())

# hoping and praying
if solver.check() == sat:
    model = solver.model()

    flag = ''
    for name in variable_names:
        var = globals()[name]     # Get the actual Bool object
        value = model.eval(var)   # Get its value in the model
        flag += "1" if value else "0"
    print(long_to_bytes(int(flag[:104],2)))

else:
    print("unsat")

# sat_on_a_caml