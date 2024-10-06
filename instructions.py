from enum import Enum, auto
from binaryninja import BranchType, InstructionInfo, RegisterName
from binaryninja.function import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType
from .defs import *
from .variation import Variation

def bit_address(val: int) -> int:
    if val < 0x80:
        return 0x20 + val // 8
    else:
        return val & 0xf8

def code_addr(x: int) -> int:
    return code_base + x
def indirect_addr(x: int) -> int:
    return imem_base + x
def direct_addr(x: int) -> int:
    if x < 0x80:
        return imem_base + x
    else:
        return sfr_base + x
def xdata_addr(x: int) -> int:
    return xdata_base + x

def is_code(x: int) -> bool:
    return 0 <= x < imem_base
def is_imem(x: int) -> bool:
    return imem_base <= x < sfr_base
def is_sfr(x: int) -> bool:
    return sfr_base <= x < xdata_base
def is_xdata(x: int) -> bool:
    return xdata_base <= x


class Operand(Enum):
    A = auto()
    R0 = auto()
    R1 = auto()
    R2 = auto()
    R3 = auto()
    R4 = auto()
    R5 = auto()
    R6 = auto()
    R7 = auto()
    DPTR = auto()
    DPTRL = auto()
    AB = auto()
    DIRECT1 = auto()
    DIRECT2 = auto()
    IMMEDIATE1 = auto()
    IMMEDIATE2 = auto()
    DPTR_IMMEDIATE = auto()
    BIT = auto()
    COMPLEMENTED_BIT = auto()
    ADDRESS11 = auto()
    ADDRESS16 = auto()
    OFFSET = auto()
    CARRY_FLAG = auto()
    AT_R0 = auto()
    AT_R1 = auto()
    AT_XDATA_R0 = auto()
    AT_XDATA_R1 = auto()
    AT_DPTR = auto()
    AT_A_PLUS_DPTR = auto()
    AT_A_PLUS_PC = auto()

    def is_bit(self) -> bool:
        match self:
            case Operand.CARRY_FLAG | Operand.BIT | Operand.COMPLEMENTED_BIT:
                return True
            case _:
                return False

    def size(self) -> int:
        match self:
            case Operand.DPTR_IMMEDIATE | Operand.ADDRESS16:
                return 2
            case (Operand.DIRECT1 | Operand.DIRECT2 | Operand.IMMEDIATE1 | Operand.IMMEDIATE2
                  | Operand.BIT | Operand.ADDRESS11 | Operand.OFFSET):
                return 1
            case _:
                return 0

    def const_address(self, data: bytes, addr: int, var: Variation) -> int:
        op = Operand
        match self:
            case op.DIRECT1:
                return direct_addr(data[1])
            case op.DIRECT2:
                return direct_addr(data[2])
            case op.BIT | op.COMPLEMENTED_BIT:
                val = data[1]
                if val < 0x80:
                    return direct_addr(0x20 + val // 8)
                else:
                    return direct_addr(val & 0xf8)
            case op.ADDRESS11:
                base = addr & -(1 << 11) & 0xffff
                hi = data[0] >> 5 << 8
                lo = data[1]
                res_addr = var.based_addr(addr, base | hi | lo)
                return code_addr(res_addr)
            case op.ADDRESS16:
                hi = data[1] << 8
                lo = data[2]
                return code_addr(var.based_addr(addr, hi | lo))
            case op.OFFSET:
                offset = data[-1] - 2 * (data[-1] & 0x80)
                res_addr = var.add_code_addr(addr, offset)
                return code_addr(res_addr)
            case _:
                raise ValueError("expected an operand with address")

    def immediate(self, data: bytes, addr: int) -> int:
        op = Operand 
        match self:
            case op.IMMEDIATE1:
                return data[1]
            case op.IMMEDIATE2:
                return data[2]
            case op.DPTR_IMMEDIATE:
                return data[1] << 8 | data[2]
            case _:
                raise ValueError("expected an operand with immediate")

    def bit(self, data: bytes, addr: int) -> int:
        op = Operand 
        match self:
            case op.BIT | op.COMPLEMENTED_BIT:
                return data[1] % 8
            case _:
                raise ValueError("expected a bit operand")


    def as_tokens(self, data: bytes, addr: int, var: Variation) -> list[InstructionTextToken]:
        Opd = Operand
        def with_at(t):
            return ([InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '@')] +
                    t +
                    [InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, '')])

        def addr_token():
            a = self.const_address(data, addr, var)
            if is_code(a) or is_xdata(a):
                return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'0x{a & mem_mask:04x}', value=a)
            reg = var.register_at_address(a)
            if reg:
                return InstructionTextToken(InstructionTextTokenType.RegisterToken, reg)
            return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, f'0x{a & mem_mask:02x}', value=a)
            
            
        match self:
            case Opd.A | Opd.R0 | Opd.R1 | Opd.R2 | Opd.R3 | Opd.R4 | Opd.R5 | Opd.R6 | Opd.R7:
                return [InstructionTextToken(InstructionTextTokenType.RegisterToken, self.name)]
            case Opd.AB:
                return [InstructionTextToken(InstructionTextTokenType.RegisterToken, self.name)]
            case Opd.DPTRL | Opd.DPTR:
                return [InstructionTextToken(InstructionTextTokenType.RegisterToken, 'DPTR')]
            case Opd.DIRECT1 | Opd.DIRECT2:
                return [addr_token()]
            case Opd.IMMEDIATE1 | Opd.IMMEDIATE2:
                val = self.immediate(data, addr)
                return [InstructionTextToken(InstructionTextTokenType.TextToken, '#'),
                        InstructionTextToken(InstructionTextTokenType.IntegerToken, f'0x{val:02x}', value=val)]
            case Opd.DPTR_IMMEDIATE:
                val = self.immediate(data, addr)
                return [InstructionTextToken(InstructionTextTokenType.TextToken, '#'),
                        InstructionTextToken(InstructionTextTokenType.IntegerToken, f'0x{val:04x}', value=val)]
            case Opd.BIT:
                bit_part = self.bit(data, addr)
                return [addr_token(),
                        InstructionTextToken(InstructionTextTokenType.TextToken, '.'),
                        InstructionTextToken(InstructionTextTokenType.IntegerToken, str(bit_part), value=bit_part)]
            case Opd.COMPLEMENTED_BIT:
                bit_part = self.bit(data, addr)
                return [InstructionTextToken(InstructionTextTokenType.TextToken, '/'),
                        addr_token(),
                        InstructionTextToken(InstructionTextTokenType.TextToken, '.'),
                        InstructionTextToken(InstructionTextTokenType.IntegerToken, str(bit_part), value=bit_part)]
            case Opd.ADDRESS11 | Opd.ADDRESS16 | Opd.OFFSET:
                return [addr_token()]
            case Opd.CARRY_FLAG:
                return [InstructionTextToken(InstructionTextTokenType.RegisterToken, 'C')]
            case Opd.AT_R0 | Opd.AT_XDATA_R0:
                return with_at([InstructionTextToken(InstructionTextTokenType.RegisterToken, 'R0')])
            case Opd.AT_R1 | Opd.AT_XDATA_R1:
                return with_at([InstructionTextToken(InstructionTextTokenType.RegisterToken, 'R1')])
            case Opd.AT_DPTR:
                return with_at([InstructionTextToken(InstructionTextTokenType.RegisterToken, 'DPTR')])
            case Opd.AT_A_PLUS_DPTR:
                return with_at([InstructionTextToken(InstructionTextTokenType.RegisterToken, 'A'),
                                InstructionTextToken(InstructionTextTokenType.TextToken, '+'),
                                InstructionTextToken(InstructionTextTokenType.RegisterToken, 'DPTR')])
            case Opd.AT_A_PLUS_PC:
                return with_at([InstructionTextToken(InstructionTextTokenType.RegisterToken, 'A'),
                                InstructionTextToken(InstructionTextTokenType.TextToken, '+'),
                                InstructionTextToken(InstructionTextTokenType.RegisterToken, 'PC')])

class Op(Enum):
    NOP = auto()
    AJMP = auto()
    LJMP = auto()
    RR = auto()
    INC = auto()
    DEC = auto()
    ACALL = auto()
    LCALL = auto()
    RRC = auto()
    MOV = auto()
    MOVC = auto()
    MOVX = auto()
    ANL = auto()
    ORL = auto()
    XRL = auto()
    CLR = auto()
    CPL = auto()
    SWAP = auto()
    MUL = auto()
    DIV = auto()
    DA = auto()
    PUSH = auto()
    POP = auto()
    SETB = auto()
    SJMP = auto()
    SUBB = auto()
    ADD = auto()
    ADDC = auto()
    RL = auto()
    RLC = auto()
    XCH = auto()
    XCHD = auto()
    RET = auto()
    RETI = auto()
    JC = auto()
    JNC = auto()
    JZ = auto()
    JNZ = auto()
    JB = auto()
    JNB = auto()
    JBC = auto()
    DJNZ = auto()
    CJNE = auto()
    JMP = auto()

class Instruction:
    length: int
    operation: Op
    operands: list[Operand]

    def __init__(self, length, operation, operands):
        self.length = length
        self.operation = operation
        self.operands = operands

    def __repr__(self):
        operands_str = ', '.join([op.name for op in self.operands])
        return (f"Instruction({self.length}, {self.operation.name}, [{operands_str}])")

    def data_addr(self, data: bytes, start_addr: int, var: Variation) -> tuple[bytes, int]:
        addr = var.add_code_addr(start_addr, self.length)
        data = data[:self.length]
        return (data, addr)

    def instruction_text(self, data: bytes, start_addr: int, var: Variation) -> list[InstructionTextToken]:
        (data, addr) = self.data_addr(data, start_addr, var)
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.operation.name)]
        if self.operands:
            tokens += [InstructionTextToken(InstructionTextTokenType.TextToken, '\t')]
            tokens += self.operands[0].as_tokens(data, addr, var)
            for operand in self.operands[1:]:
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', ')]
                tokens += operand.as_tokens(data, addr, var)
        return tokens
    
    def instruction_info(self, data: bytes, start_addr: int, var: Variation):
        result = InstructionInfo() 
        (data, addr) = self.data_addr(data, start_addr, var)
        result.length = self.length
        match self.operation:
            case Op.RET | Op.RETI:
                result.add_branch(branch_type=BranchType.FunctionReturn)
            case Op.LJMP | Op.AJMP | Op.SJMP:
                target = self.operands[-1].const_address(data, addr, var)
                result.add_branch(branch_type=BranchType.UnconditionalBranch, target=target)
            case Op.JMP:
                result.add_branch(branch_type=BranchType.IndirectBranch)
            case Op.JC | Op.JNC | Op.JZ | Op.JNZ | Op.JB | Op.JNB | Op.JBC | Op.DJNZ | Op.CJNE:
                result.add_branch(branch_type=BranchType.FalseBranch, target=start_addr + self.length)
                target = self.operands[-1].const_address(data, addr, var)
                result.add_branch(branch_type=BranchType.TrueBranch, target=target)
            case Op.LCALL | Op.ACALL:
                target = self.operands[-1].const_address(data, addr, var)
                result.add_branch(branch_type=BranchType.CallDestination, target=target)
        return result



instructions = [
    Instruction(1, Op.NOP, []),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(3, Op.LJMP, [Operand.ADDRESS16]),
    Instruction(1, Op.RR, [Operand.A]),
    Instruction(1, Op.INC, [Operand.A]),
    Instruction(2, Op.INC, [Operand.DIRECT1]),
    Instruction(1, Op.INC, [Operand.AT_R0]),
    Instruction(1, Op.INC, [Operand.AT_R1]),
    Instruction(1, Op.INC, [Operand.R0]),
    Instruction(1, Op.INC, [Operand.R1]),
    Instruction(1, Op.INC, [Operand.R2]),
    Instruction(1, Op.INC, [Operand.R3]),
    Instruction(1, Op.INC, [Operand.R4]),
    Instruction(1, Op.INC, [Operand.R5]),
    Instruction(1, Op.INC, [Operand.R6]),
    Instruction(1, Op.INC, [Operand.R7]),
    Instruction(3, Op.JBC, [Operand.BIT, Operand.OFFSET]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(3, Op.LCALL, [Operand.ADDRESS16]),
    Instruction(1, Op.RRC, [Operand.A]),
    Instruction(1, Op.DEC, [Operand.A]),
    Instruction(2, Op.DEC, [Operand.DIRECT1]),
    Instruction(1, Op.DEC, [Operand.AT_R0]),
    Instruction(1, Op.DEC, [Operand.AT_R1]),
    Instruction(1, Op.DEC, [Operand.R0]),
    Instruction(1, Op.DEC, [Operand.R1]),
    Instruction(1, Op.DEC, [Operand.R2]),
    Instruction(1, Op.DEC, [Operand.R3]),
    Instruction(1, Op.DEC, [Operand.R4]),
    Instruction(1, Op.DEC, [Operand.R5]),
    Instruction(1, Op.DEC, [Operand.R6]),
    Instruction(1, Op.DEC, [Operand.R7]),
    Instruction(3, Op.JB, [Operand.BIT, Operand.OFFSET]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(1, Op.RET, []),
    Instruction(1, Op.RL, [Operand.A]),
    Instruction(2, Op.ADD, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.ADD, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.ADD, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.ADD, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R0]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R1]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R2]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R3]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R4]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R5]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R6]),
    Instruction(1, Op.ADD, [Operand.A, Operand.R7]),
    Instruction(3, Op.JNB, [Operand.BIT, Operand.OFFSET]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(1, Op.RETI, []),
    Instruction(1, Op.RLC, [Operand.A]),
    Instruction(2, Op.ADDC, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.ADDC, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R0]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R1]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R2]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R3]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R4]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R5]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R6]),
    Instruction(1, Op.ADDC, [Operand.A, Operand.R7]),
    Instruction(2, Op.JC, [Operand.OFFSET]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(2, Op.ORL, [Operand.DIRECT1, Operand.A]),
    Instruction(3, Op.ORL, [Operand.DIRECT1, Operand.IMMEDIATE2]),
    Instruction(2, Op.ORL, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.ORL, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.ORL, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.ORL, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R0]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R1]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R2]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R3]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R4]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R5]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R6]),
    Instruction(1, Op.ORL, [Operand.A, Operand.R7]),
    Instruction(2, Op.JNC, [Operand.OFFSET]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(2, Op.ANL, [Operand.DIRECT1, Operand.A]),
    Instruction(3, Op.ANL, [Operand.DIRECT1, Operand.IMMEDIATE2]),
    Instruction(2, Op.ANL, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.ANL, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.ANL, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.ANL, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R0]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R1]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R2]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R3]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R4]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R5]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R6]),
    Instruction(1, Op.ANL, [Operand.A, Operand.R7]),
    Instruction(2, Op.JZ, [Operand.OFFSET]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(2, Op.XRL, [Operand.DIRECT1, Operand.A]),
    Instruction(3, Op.XRL, [Operand.DIRECT1, Operand.IMMEDIATE2]),
    Instruction(2, Op.XRL, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.XRL, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.XRL, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.XRL, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R0]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R1]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R2]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R3]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R4]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R5]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R6]),
    Instruction(1, Op.XRL, [Operand.A, Operand.R7]),
    Instruction(2, Op.JNZ, [Operand.OFFSET]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(2, Op.ORL, [Operand.CARRY_FLAG, Operand.BIT]),
    Instruction(1, Op.JMP, [Operand.AT_A_PLUS_DPTR]),
    Instruction(2, Op.MOV, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(3, Op.MOV, [Operand.DIRECT1, Operand.IMMEDIATE2]),
    Instruction(2, Op.MOV, [Operand.AT_R0, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.AT_R1, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R0, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R1, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R2, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R3, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R4, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R5, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R6, Operand.IMMEDIATE1]),
    Instruction(2, Op.MOV, [Operand.R7, Operand.IMMEDIATE1]),
    Instruction(2, Op.SJMP, [Operand.OFFSET]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(2, Op.ANL, [Operand.CARRY_FLAG, Operand.BIT]),
    Instruction(1, Op.MOVC, [Operand.A, Operand.AT_A_PLUS_PC]),
    Instruction(1, Op.DIV, [Operand.AB]),
    Instruction(3, Op.MOV, [Operand.DIRECT2, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.AT_R0]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.AT_R1]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R0]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R1]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R2]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R3]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R4]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R5]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R6]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.R7]),
    Instruction(3, Op.MOV, [Operand.DPTRL, Operand.DPTR_IMMEDIATE]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(2, Op.MOV, [Operand.BIT, Operand.CARRY_FLAG]),
    Instruction(1, Op.MOVC, [Operand.A, Operand.AT_A_PLUS_DPTR]),
    Instruction(2, Op.SUBB, [Operand.A, Operand.IMMEDIATE1]),
    Instruction(2, Op.SUBB, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R0]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R1]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R2]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R3]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R4]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R5]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R6]),
    Instruction(1, Op.SUBB, [Operand.A, Operand.R7]),
    Instruction(2, Op.ORL, [Operand.CARRY_FLAG, Operand.COMPLEMENTED_BIT]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(2, Op.MOV, [Operand.CARRY_FLAG, Operand.BIT]),
    Instruction(1, Op.INC, [Operand.DPTR]),
    Instruction(1, Op.MUL, [Operand.AB]),
    None,
    Instruction(2, Op.MOV, [Operand.AT_R0, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.AT_R1, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R0, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R1, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R2, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R3, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R4, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R5, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R6, Operand.DIRECT1]),
    Instruction(2, Op.MOV, [Operand.R7, Operand.DIRECT1]),
    Instruction(2, Op.ANL, [Operand.CARRY_FLAG, Operand.COMPLEMENTED_BIT]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(2, Op.CPL, [Operand.BIT]),
    Instruction(1, Op.CPL, [Operand.CARRY_FLAG]),
    Instruction(3, Op.CJNE, [Operand.A, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.A, Operand.DIRECT1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.AT_R0, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.AT_R1, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R0, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R1, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R2, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R3, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R4, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R5, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R6, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(3, Op.CJNE, [Operand.R7, Operand.IMMEDIATE1, Operand.OFFSET]),
    Instruction(2, Op.PUSH, [Operand.DIRECT1]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(2, Op.CLR, [Operand.BIT]),
    Instruction(1, Op.CLR, [Operand.CARRY_FLAG]),
    Instruction(1, Op.SWAP, [Operand.A]),
    Instruction(2, Op.XCH, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.XCH, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.XCH, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R0]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R1]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R2]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R3]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R4]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R5]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R6]),
    Instruction(1, Op.XCH, [Operand.A, Operand.R7]),
    Instruction(2, Op.POP, [Operand.DIRECT1]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(2, Op.SETB, [Operand.BIT]),
    Instruction(1, Op.SETB, [Operand.CARRY_FLAG]),
    Instruction(1, Op.DA, [Operand.A]),
    Instruction(3, Op.DJNZ, [Operand.DIRECT1, Operand.OFFSET]),
    Instruction(1, Op.XCHD, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.XCHD, [Operand.A, Operand.AT_R1]),
    Instruction(2, Op.DJNZ, [Operand.R0, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R1, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R2, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R3, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R4, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R5, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R6, Operand.OFFSET]),
    Instruction(2, Op.DJNZ, [Operand.R7, Operand.OFFSET]),
    Instruction(1, Op.MOVX, [Operand.A, Operand.AT_DPTR]),
    Instruction(2, Op.AJMP, [Operand.ADDRESS11]),
    Instruction(1, Op.MOVX, [Operand.A, Operand.AT_XDATA_R0]),
    Instruction(1, Op.MOVX, [Operand.A, Operand.AT_XDATA_R1]),
    Instruction(1, Op.CLR, [Operand.A]),
    Instruction(2, Op.MOV, [Operand.A, Operand.DIRECT1]),
    Instruction(1, Op.MOV, [Operand.A, Operand.AT_R0]),
    Instruction(1, Op.MOV, [Operand.A, Operand.AT_R1]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R0]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R1]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R2]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R3]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R4]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R5]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R6]),
    Instruction(1, Op.MOV, [Operand.A, Operand.R7]),
    Instruction(1, Op.MOVX, [Operand.AT_DPTR, Operand.A]),
    Instruction(2, Op.ACALL, [Operand.ADDRESS11]),
    Instruction(1, Op.MOVX, [Operand.AT_XDATA_R0, Operand.A]),
    Instruction(1, Op.MOVX, [Operand.AT_XDATA_R1, Operand.A]),
    Instruction(1, Op.CPL, [Operand.A]),
    Instruction(2, Op.MOV, [Operand.DIRECT1, Operand.A]),
    Instruction(1, Op.MOV, [Operand.AT_R0, Operand.A]),
    Instruction(1, Op.MOV, [Operand.AT_R1, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R0, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R1, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R2, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R3, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R4, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R5, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R6, Operand.A]),
    Instruction(1, Op.MOV, [Operand.R7, Operand.A]),
]

def get_instr(data: bytes, addr: int) -> Instruction | None:
    try:
        opcode = data[0]
    except IndexError:
        return None

    instr = instructions[opcode]
    if instr == None:
        return None
    
    if instr.length > len(data):
        return None
    
    return instr