# IDAPython---NOP-Instruction-pattern
IDA Python script to nop instructions that matches arbitrary assembly pattern

# Version
Fully functional in IDA Pro 7.7 with python 3.11.5. No tests were done in other IDA or Python versions.

# Why?
While reversing software in IDA Pro, I've found that a specific code was making use of some specific junk assembly code patterns to trick the decompiler into wrong decompilation, repeatedly. To solve this issue I wrote an script to automate the detection of all the code that matches the pattern in the __text section of the binary and NOP them. It solved decompilation issues.

# Architecture
It can match whatever assembly code you write in any architecture, the thing is the NOP bytes is written for little-endian ARM64 (0x1F2003D5), although you can edit it to fit any other instruction of your like. also the iteration through the __text section blob is spected to step 4 bytes for every single instruction as all ARM64 instructions are 4 bytes only, again, you can easily edit it to fit your needs.

# How to use?
Go to IDA -> File -> Script File. Select the script file and wait for it to run. It should patch all the patterns and show it's output in the Output Window.
