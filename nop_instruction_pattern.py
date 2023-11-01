import idautils
import idc
import ida_bytes as idabytes
import ida_segment as idasegm
import ida_ua as idaua

NOP = b'\x1F\x20\x03\xD5'

def read_instruction(address):
    mnem = idc.print_insn_mnem(address)
    op1 = idc.print_operand(address, 0)
    op2 = idc.print_operand(address, 1)
    op3 = idc.print_operand(address, 2)
    op4 = idc.print_operand(address, 3)
    op5 = idc.print_operand(address, 4)

    # generate whole instruction
    inst = mnem
    if op1 != '':
        inst += ' ' + op1
    if op2 != '':
        inst += ', ' + op2
    if op3 != '':
        inst += ', ' + op3
    if op4 != '':
        inst += ', ' + op4
    if op5 != '':
        inst += ', ' + op5
    
    return inst

# find consecutive mnemonic that matches the given pattern and patch them with NOP's
def nop_mnem_pattern(pattern):
    print("[*] Starting...")
    segment = idasegm.get_segm_by_name("__text")
    if segment:
        matches = []
        inst_size = 4
        insts_num = int((segment.end_ea - segment.start_ea) / inst_size)
        for x in range(insts_num):
            address = int(segment.start_ea + (x * inst_size))
            if idaua.can_decode(address):
                mnem = idc.print_insn_mnem(address)
                remaining_bytes = segment.end_ea - address
                if mnem == pattern[0] and remaining_bytes > len(pattern) * inst_size:
                    for j in range(1, len(pattern)):
                        _address = int(address + (j * inst_size))
                        _mnem = idc.print_insn_mnem(_address)
                        if _mnem != pattern[j]:
                            break
                    else:
                        matches.append(address)
        if len(matches) > 0:
            print("[+] Found {} matches".format(len(matches)))
            print("[*] Patching them all...")
            for match_start_address in matches:
                for i in range(len(pattern)):
                    address = match_start_address + (i * inst_size)
                    idabytes.patch_bytes(address, NOP)
            print("[+] All patches have been applied!")
        else:
            print("[-] No matches were found")

# matches consective instructions and patch them with NOP's
def nop_insn_pattern(pattern):
    print("[*] Starting...")
    segment = idasegm.get_segm_by_name("__text")
    if segment:
        matches = []
        inst_size = 4
        insts_num = int((segment.end_ea - segment.start_ea) / inst_size)
        for x in range(insts_num):
            address = int(segment.start_ea + (x * inst_size))
            if idaua.can_decode(address):
                cur_inst = read_instruction(address)
                remaining_bytes = segment.end_ea - address
                if pattern[0] in cur_inst and remaining_bytes > len(pattern) * inst_size:
                    for j in range(1, len(pattern)):
                        _address = int(address + (j * inst_size))
                        _cur_inst = read_instruction(_address)
                        if pattern[j] not in _cur_inst:
                            break
                    else:
                        matches.append(address)
        if len(matches) > 0:
            print("[+] Found {} matches".format(len(matches)))
            print("[*] Patching them all...")
            for match_start_address in matches:
                for i in range(len(pattern)):
                    address = match_start_address + (i * inst_size)
                    idabytes.patch_bytes(address, NOP)
        else:
            print("[-] No matches were found")

# mnemonic patterns to patch, None stands for literal pool (data in middle of __text section code as it can't be disassembled and the disassembler returns None instead of the given mnemonic)
nop_mnem_pattern(["STUR", "LDUR", "ADR", "LDRSW", "ADD", "AND", "MOV", "MUL", "EOR", "ADD", "BR", None])
nop_mnem_pattern(["STR", "LDR", "ADR", "LDRSW", "ADD", "AND", "MOV", "MUL", "EOR", "ADD", "BR", None])
nop_mnem_pattern(["STUR", "LDUR", "ADR", "AND", "MOV", "MUL", "EOR", "ADD", "BR"])


# new pattern
#28 00 80 D2 - MOV             X8, #1
#69 00 00 10 - ADR             X9, loc_XXXXX
#28 7D 08 9B - MUL             X8, X9, X8
#00 01 1F D6 - BR              X8
nop_insn_pattern(["MOV X8, #1", 
                  "ADR X9", 
                  "MUL X8, X9, X8", 
                  "BR X8"])


# new pattern
#__text:000000000006521C E9 00 00 10                       ADR             X9, loc_65238
#__text:0000000000065220 29 01 0B CB                       SUB             X9, X9, X11
#__text:0000000000065224 FF 23 00 D1                       SUB             SP, SP, #8
#__text:0000000000065228 02 00 00 14                       B               loc_65230
#__text:000000000006522C 29 01 0B CB                       SUB             X9, X9, X11
#__text:0000000000065230 29 01 0B 8B                       ADD             X9, X9, X11
#__text:0000000000065234 20 01 1F D6                       BR              X9
nop_insn_pattern(["ADR X9", 
                  "SUB X9, X9, X11", 
                  "SUB SP, SP, #8", 
                  "B", # branch 
                  "SUB X9, X9, X11", 
                  "ADD X9, X9, X11", 
                  "BR X9"])

# new pattern
# __text:000000000005965C FF 0F 00 F9                       STR             XZR, [SP,#0x50+var_38]
# __text:0000000000059660 EB 0F 40 F9                       LDR             X11, [SP,#0x50+var_38]
# __text:0000000000059664 E8 00 00 10                       ADR             X8, loc_59680
# __text:0000000000059668 09 01 0B 8A                       AND             X9, X8, X11
# __text:000000000005966C 4A 00 80 D2                       MOV             X10, #2
# __text:0000000000059670 29 7D 0A 9B                       MUL             X9, X9, X10
# __text:0000000000059674 08 01 0B CA                       EOR             X8, X8, X11
# __text:0000000000059678 08 01 09 8B                       ADD             X8, X8, X9
# __text:000000000005967C 00 01 1F D6                       BR              X8
nop_insn_pattern(["STR XZR", 
                  "LDR X11", 
                  "ADR X8", 
                  "AND X9, X8, X11", 
                  "MOV X10, #2", 
                  "MUL X9, X9, X10", 
                  "EOR X8, X8, X11", 
                  "ADD X8, X8, X9", 
                  "BR X8"])


# new pattern
#__text:00000000000472F0 BF 83 1B F8                       STUR            XZR, [X29,#var_48]
#__text:00000000000472F4 AB 83 5B F8                       LDUR            X11, [X29,#var_48]
#__text:00000000000472F8 E8 00 00 10                       ADR             X8, unk_47314
#__text:00000000000472FC 09 01 0B 8A                       AND             X9, X8, X11
#__text:0000000000047300 4A 00 80 D2                       MOV             X10, #2
#__text:0000000000047304 29 7D 0A 9B                       MUL             X9, X9, X10
#__text:0000000000047308 08 01 0B CA                       EOR             X8, X8, X11
#__text:000000000004730C 08 01 09 8B                       ADD             X8, X8, X9
#__text:0000000000047310 00 01 1F D6                       BR              X8
nop_insn_pattern(["STUR XZR", 
                  "LDUR X11", 
                  "ADR X8", 
                  "AND X9, X8, X11", 
                  "MOV X10, #2", 
                  "MUL X9, X9, X10", 
                  "EOR X8, X8, X11", 
                  "ADD X8, X8, X9", 
                  "BR X8"])

# new pattern
#__text:00000000000473C4 BF 83 17 F8                       STUR            XZR, [X29,#var_88]
#__text:00000000000473C8 AB 83 57 F8                       LDUR            X11, [X29,#var_88]
#__text:00000000000473CC E8 00 00 10                       ADR             X8, loc_473E8
#__text:00000000000473D0 09 01 0B 8A                       AND             X9, X8, X11
#__text:00000000000473D4 4A 00 80 D2                       MOV             X10, #2
#__text:00000000000473D8 29 7D 0A 9B                       MUL             X9, X9, X10
#__text:00000000000473DC 08 01 0B CA                       EOR             X8, X8, X11
#__text:00000000000473E0 08 01 09 8B                       ADD             X8, X8, X9
#__text:00000000000473E4 00 01 1F D6                       BR              X8
nop_insn_pattern(["STUR XZR", 
                  "LDUR X11", 
                  "ADR X8", 
                  "AND X9, X8, X11", 
                  "MOV X10, #2", 
                  "MUL X9, X9, X10", 
                  "EOR X8, X8, X11", 
                  "ADD X8, X8, X9", 
                  "BR X8"])
