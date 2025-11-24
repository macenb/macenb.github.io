import string

def process_code_file_c_logic(filepath):
    data_array = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as fp:
            for line in fp:
                if line.endswith('\n'):
                    processed_line = line.rstrip('\n')
                else:
                    processed_line = line
                    
                data_array.append(processed_line)
                
        # Report the final structure
        lines = len(data_array)
        # print(f"File processing complete.")
        # print(f"Total number of lines (C 'lines' variable): {lines}")
        # print("-" * 30)
        
        # Display the stored data_array in a readable format
        # for i, stored_line in enumerate(data_array):
        #     print(f"Line [{i:02}]: '{stored_line}'")
            
        return data_array

    except FileNotFoundError:
        print(f"Error: The file at {filepath} was not found.")
        return []
    except Exception as e:
        print(f"An error occurred during file reading: {e}")
        return []

code = process_code_file_c_logic('program.txt')


def flag_guess(guess):
    stack = [0] * 0x102
    sp = 0
    line = 0
    col = 0
    flag_idx = 0
    while True:
        match ord(code[line][col]):
            case 0x2194:
                # if stack[sp] == 0: sp++; else sp--;
                if stack[sp] != 0:
                    col -= 1
                else:
                    col += 1
                # print("check zero move column", end=' ; ')
            case 0x2195:
                # if stack[sp] == 0: sp++; else sp--;
                if stack[sp] != 0:
                    line -= 1
                else:
                    line += 1
                # print("check zero move line", end=' ; ')
            case 0x219e:
                sp -= 1
                col -= 1
                # print("dec stack & col", end=' ; ')
            case 0x219f:
                stack[sp] += 1
                line -= 1
                # print("stack[sp]++ & line--", end=' ; ')
            case 0x21a0:
                sp += 1
                col += 1
                # print("sp++, col++", end=' ; ')
            case 0x21a1:
                stack[sp] -= 1
                line += 1
                # print("stack[sp]-- & line++", end=' ; ')
            case 0x21d1:
                if flag_idx >= len(guess):
                    return 0
                stack[sp] = ord(guess[flag_idx])
                flag_idx += 1
                # print(stack)
                line -= 1
            case 0x21d3:
                print(stack[sp], end='')
                line += 1
            case 0x21e0: # left
                col -= 1
                # print("col--", end=' ; ')
            case 0x21e1: # up
                line -= 1
                # print("line--", end=' ; ')
            case 0x21e2: # right
                col += 1
                # print("col++", end=' ; ')
            case 0x21e3: # down
                line += 1
                # print("line++", end=' ; ')
            case 0x0:
                pass
            case 0x2e:
                return -1
                break
            case _:
                print("Unknown instruction:", hex(ord(code[line][col])))
                break

flag = ''
while True:
    for i in string.printable:
        test_flag = flag + i
        result = flag_guess(test_flag)
        if result == 0:
            flag += i
            if i == '}':
                print(f"Flag found: {flag}")
                exit(0)
            print(f"Found character: {i} -> Current flag: {flag}")
            break