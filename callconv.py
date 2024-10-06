from binaryninja import CallingConvention
from .defs import *

class KeilCC(CallingConvention):
    caller_saved_regs = [R0, R1, R2, R3, R4, R5, R6, R7, A, B, DPTR]
    callee_saved_regs = []
    int_arg_regs = [R7, R6, R5, R4, R3, R2, R1]
    int_return_reg = R7
    high_int_return_reg = R6

class IARCC(CallingConvention):
    caller_saved_regs = [R0, R1, R2, R3, R4, R5, A, B, DPTR]
    callee_saved_regs = [R6, R7]
    int_arg_regs = [R1, R2, R3, R4, R5]
    int_return_reg = R1

class AVRBankedCC(CallingConvention):
    caller_saved_regs = [R0, R1, R2, R3, R4, R5, A, B]
    callee_saved_regs = [R6, R7, DPTR]
    int_arg_regs = [R1, R2, R3, R4, R5]
    int_return_reg = R1