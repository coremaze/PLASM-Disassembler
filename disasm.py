import struct
import argparse

SYSCALL_INFO  = {
    0: "??? for logging or printing",
    110: "??? CREATE VECTOR* (stack@1= size??) returns vector*",
    124: "WRITE TO BUFFER (stack@1 value, stack@2 offset, stack@3 vector*)",
    132: "READ FROM BUFFER (stack@1 offset, stack@2 vector*)",
    140: "GET SIZE OF VECTOR* (stack@1 = vector*) returns size",
    148: "??? RESIZE VECTOR (stack@1= size, stack@2=vector*)",
    264: "??? stores data from PLX into a vector* contained by stack@1, maybe from httpclient",
    340: "??? strcmp"
    }

def Disassemble(listing, pc):
    max_offset = max(list(listing))
    while True:
        if pc > max_offset: return
        if type(listing[pc]) == str:
            print(f'Recurse collision at {pc:04X}')
            return

        argument = listing[pc+1]
        
        if listing[pc] == 0x05:
            listing[pc] = f'PUSH32'
            del listing[pc+1]
            pc += 2
            
        elif listing[pc] == 0xC:
            listing[pc] = f'RET {argument}'
            del listing[pc+1]
            #return
            pc += 2

        elif listing[pc] == 0x12: #CALL
            listing[pc] = f'CALL ${argument:04X}'
            del listing[pc+1]
            #Disassemble(listing, argument)
            pc += 2

        elif listing[pc] == 0x13:
            string = ''
            for i in range(argument):
                string += chr(listing[pc+2+i])
                del listing[pc+2+i]
            listing[pc] = f'PUSHSTR "{string}"'
            del listing[pc+1]
            pc += 2 + argument

        elif listing[pc] == 0x14:
            listing[pc] = f'CMPGE'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x17:
            listing[pc] = f'ADD'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x1B:
            listing[pc] = f'LOADVAR @{argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x24:
            listing[pc] = f'STOREVAR @{argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x2C:
            listing[pc] = f'NEWFRAME offset {argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x3A:
            listing[pc] = f'POP {argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x3B:
            listing[pc] = f'BOOLAND'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x43:
            listing[pc] = f'PUSH {argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x44:
            listing[pc] = f'PUSH2 {argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x4A:
            listing[pc] = f'MUL'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x56:
            listing[pc] = f'DIV'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x5C:
            listing[pc] = f'MOD'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x63:
            listing[pc] = f'SUB'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x69:
            listing[pc] = f'CMPEQ'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x71:
            listing[pc] = f'CMPLT'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x73:
            dest = pc + argument + 2
            listing[pc] = f'BRZ -> ${dest:04X}'
            del listing[pc+1]
            #Disassemble(listing, dest)
            pc += 2

        elif listing[pc] == 0x74:
            listing[pc] = f'LOADPTR @{argument}'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x75:
            listing[pc] = f'CMPZ'
            del listing[pc+1]
            pc += 2

        elif listing[pc] == 0x86:
            dest = pc + argument + 2
            listing[pc] = f'BRA -> ${dest:04X}'
            del listing[pc+1]
            #Disassemble(listing, dest)
            pc += 2

        elif listing[pc] == 0x89:
            listing[pc] = f'SYSCALL {argument}'
            syscall_info = SYSCALL_INFO.get(argument, None)
            if syscall_info:
                listing[pc] = '\t'.join((listing[pc], f'// {syscall_info}'))
            del listing[pc+1]
            pc += 2
            
        else: #unrecognized
            listing[pc] = f'??? ${argument:04X} {hex(listing[pc+1])}'
            del listing[pc+1]
            pc += 2


##def Disassemble2(listing, pc=0):
##    opcodes = set()
##    max_offset = max(list(listing))
##    while True:
##        if pc > (max_offset): return opcodes
##        if listing[pc] in (0x13,):
##            opcodes.add(listing[pc])
##            char_count = listing[pc+1]
##            string = ''
##            for i in range(char_count):
##                string += chr(listing[pc+2+i])
##                del listing[pc+2+i]
##            listing[pc] = f'PUSHSTR "{string}"'
##            del listing[pc+1]
##            pc += 2 + char_count
##        else:
##            opcodes.add(listing[pc])
##            listing[pc] = f'??? {hex(listing[pc])} {hex(listing[pc+1])}'
##            del listing[pc+1]
##            pc += 2

#opcodes = Disassemble2(listing)


def MakeLines(listing):
    lines = []
    for i in listing:
        lines.append(f'{i:04X}\t{listing[i]}')
    return lines


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="File to be disassembled", type=str)
    parser.add_argument("output", help="File to create", type=str)
    parser.add_argument("--decoded", help="Binary has already been deobfuscated", action="store_true")
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        data = f.read()

    dwords = []    
    for i in range(0, len(data)-1, 4):
        dwords.append(struct.unpack('<i', data[i:i+4])[0])

    if not args.decoded:
        for i in range(len(dwords)):
            dwords[i] = i - dwords[i]

    listing = {i:e for i,e in enumerate(dwords)}

    Disassemble(listing, 0)

    with open(args.output, 'w') as f:
        f.write('\n'.join(MakeLines(listing)))
    
if __name__ == '__main__':
    main()
