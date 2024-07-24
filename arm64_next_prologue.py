import re, idaapi, ida_ua, idc

def get_section(section_name):
    """List all sections and their addresses in the current Mach-O file."""
    sections = []
    for i in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(i)
        if seg:
            seg_name = idaapi.get_segm_name(seg)
            if seg_name == section_name:
                start_addr = seg.start_ea
                end_addr = seg.end_ea
                return { 'name': seg_name, 'start': start_addr, 'end': end_addr }
    return None

def disassemble_instructions(ea, count):
    """Disassemble `count` instructions starting from address `ea`."""
    instructions = []
    for _ in range(count):
        insn_t = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn_t, ea):
            break
        disasm = idc.generate_disasm_line(ea, 0)
        instructions.append(disasm)
        ea += insn_t.size
    return instructions

def match_prologue(instructions):
    # Define a regex pattern to match typical ARM64 function prologue instructions
    patterns = [
        re.compile(r'^\s*SUB\s+SP,\s*SP,\s*.+\s*|\s*STP\s+X[0-9]+,\s*X[0-9]+,\s*\[SP,.+\]!?\s*$'),    # Stack pointer adjustment
        re.compile(r'^\s*STP\s+X[0-9]+,\s*X[0-9]+,\s*\[SP,.+\]!?\s*|\s*ADD\s+X29, SP, .+\s*$'),  # Save frame pointer and link
    ]

    i = 0
    matches = 0
    match_index = -1
    for index, instruction in enumerate(instructions):
        if patterns[i].match(instruction):
            if match_index == -1:
                match_index = index
            matches += 1
            if i == 0:
                i = 1

    if matches >= 3:
        return True, match_index
    return False, -1

def find_next_prologue(start_ea):
    ea = start_ea
    text_end_ea = get_section('__text')['end']
    if text_end_ea is None:
        print("Could not find the __text section end address.")
        return

    while ea < text_end_ea:
        instructions = disassemble_instructions(ea, 8)
        if not instructions:
            print("No more instructions to analyze.")
            break
        match, i = match_prologue(instructions)
        if match:
            print(f"Found prologue at address {(ea + (i * 4)):#x}")
            break

        # Move to the next instruction for the next batch
        ea += ida_ua.decode_insn(ida_ua.insn_t(), ea)

# Find the start address of the __text section
start_ea = idc.get_screen_ea()
find_next_prologue(start_ea)
