# IDAPython---NOP-Instruction-pattern
IDA Python script to nop instructions that matches arbitrary assembly pattern

# Architecture
It can match whatever assembly code you write in any architecture, the thing is the NOP bytes is written for little-endian ARM64 (0x1F2003D5), although you can edit it to fit any other instruction of your like. also the iteration through the __text section blob is spected to follow 4 bytes for every instructions
as all ARM64 instructions are 4 bytes only, again, you can easily edit it to fit your needs.

# Why?
While reversing software in IDA Pro, I've found that a specific code was using of some junk assembly patterns to trick the decompiler into wrong decompilation all over the code, this pattern was being repeated all the time, so I had to write an automated software to detect this pattern and patch them with NOPS
so I could decompile it nicely.

# How to use?
Go to IDA -> File -> Script File. Select the script file and wait for it to run. It should patch all the patterns and show it's output in the Output Window.
