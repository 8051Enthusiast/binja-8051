from binaryninja import FlagName, RegisterName

[SP, DPTR, DPTRL, A, B, PSW] = [RegisterName(x) for x in ["SP", "DPTR", "DPTRL", "A", "B", "PSW"]]
[R0, R1, R2, R3, R4, R5, R6, R7] = [RegisterName(f'R{i}') for i in range(8)]
[DPL, DPH, DPX] = [RegisterName(x) for x in ["DPL", "DPH", "DPX"]]
C = FlagName('C')
OV = FlagName('OV')
AC = FlagName('AC')

# we put code_base at 0 for easy binary loading
code_base = 0x00 << 24
imem_base = 0x40 << 24
sfr_base = 0x80 << 24
xdata_base = 0xc0 << 24
mem_mask = (1 << 24) - 1

internal_addr_size = 4