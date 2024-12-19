from binaryninja import LLIL_TEMP, Architecture, LowLevelILLabel, RegisterName
from .instructions import Operand as Opd, Op, Instruction, code_base, xdata_base, imem_base, sfr_base, code_addr
from .variant import Variant
from .defs import *
from binaryninja.lowlevelil import LowLevelILFunction, ExpressionIndex


SP_ADDRESS = sfr_base + 0x81

def cmp_zero(il: LowLevelILFunction, b: ExpressionIndex) -> ExpressionIndex:
    return il.compare_equal(1, b, il.const(1, 0))

def read_const_address(il: LowLevelILFunction, addr: int, var: Variant) -> ExpressionIndex:
    if addr == SP_ADDRESS:
        return il.sub(1, il.reg(1, SP), il.const(1, 1))
    match var.register_at_address(addr):
        case str(reg_name):
            return il.reg(1, reg_name)
        case None:
            return il.load(1, il.const(internal_addr_size, addr))


def write_const_address(il: LowLevelILFunction, addr: int, var: Variant, val: ExpressionIndex) -> ExpressionIndex:
    if addr == SP_ADDRESS:
        val = il.add(1, val, il.const(1, 1))
        return il.set_reg(1, SP, val)
    match var.register_at_address(addr):
        case str(reg_name):
            return il.set_reg(1, reg_name, val)
        case None:
            return il.store(1, il.const(internal_addr_size, addr), val)


def adjust_banked_code_address(il: LowLevelILFunction, code_addr: ExpressionIndex, pc: int, var: Variant) -> ExpressionIndex:
    if not var.bank_size:
        return code_addr
    (bank, _) = var.bank_and_local_addr(pc)
    if bank == 0:
        return code_addr
    adjustment = bank * var.bank_size
    tmp = LLIL_TEMP(2)
    changed = LowLevelILLabel()
    unchanged = LowLevelILLabel()
    merge = LowLevelILLabel()
    needs_change = il.compare_unsigned_greater_equal(2, code_addr, il.const(2, var.bank_base()))
    il.append(il.if_expr(needs_change, changed, unchanged))
    il.mark_label(changed)
    val = il.add(internal_addr_size, il.zero_extend(internal_addr_size, code_addr), il.const(internal_addr_size, adjustment))
    il.append(il.set_reg(internal_addr_size, tmp, val))
    il.append(il.goto(merge))
    il.mark_label(unchanged)
    il.append(il.set_reg(internal_addr_size, tmp, il.zero_extend(internal_addr_size, code_addr)))
    il.append(il.goto(merge))
    il.mark_label(merge)
    return il.reg(internal_addr_size, tmp)

def calculate_dyn_address(il: LowLevelILFunction, op: Opd, pc: int, var: Variant) -> ExpressionIndex:
    match op:
        case Opd.AT_R0:
            offset = il.reg(1, R0)
            base = imem_base

        case Opd.AT_R1:
            offset = il.reg(1, R1)
            base = imem_base

        case Opd.AT_XDATA_R0:
            offset = il.reg(1, R0)
            base = xdata_base

        case Opd.AT_XDATA_R1:
            offset = il.reg(1, R1)
            base = xdata_base

        case Opd.AT_DPTR:
            offset = il.reg(var.xdata_size(), DPTR)
            base = xdata_base

        case Opd.AT_A_PLUS_PC:
            (_, local) = var.bank_and_local_addr(pc)
            local_end = local + 256
            if local_end <= var.bank_base() or local >= var.bank_base() and local_end <= 0x10000:
                # the addition does not cross any bank boundary
                offset = il.add(internal_addr_size, il.reg(1, A), il.const(internal_addr_size, pc))
            else:
                offset = il.add(2, il.zero_extend(2, il.reg(1, A)), il.const(2, local))
                offset = adjust_banked_code_address(il, offset, pc, var)
            base = code_base

        case Opd.AT_A_PLUS_DPTR:
            offset = il.add(2, il.zero_extend(2, il.reg(1, A)), il.reg(2, DPTR))
            offset = adjust_banked_code_address(il, offset, pc, var)
            base = code_base

        case _:
            raise ValueError

    offset = il.zero_extend(internal_addr_size, offset)
    if base == 0:
        return offset
    else:
        return il.add(
            internal_addr_size,
            il.const(internal_addr_size, base),
            offset
        )
            

def read_operand(il: LowLevelILFunction, op: Opd, data: bytes, addr: int, var: Variant) -> ExpressionIndex:
    match op:
        case Opd.A | Opd.R0 | Opd.R1 | Opd.R2 | Opd.R3 | Opd.R4 | Opd.R5 | Opd.R6 | Opd.R7:
            return il.reg(1, RegisterName(op.name))

        case Opd.DIRECT1 | Opd.DIRECT2:
            return read_const_address(il, op.const_address(data, addr, var), var)

        case Opd.IMMEDIATE1 | Opd.IMMEDIATE2:
            return il.const(1, op.immediate(data, addr))

        case Opd.DPTR_IMMEDIATE:
            return il.const(2, op.immediate(data, addr))
        
        case Opd.DPTR:
            return il.reg(var.xdata_size(), DPTR)

        case Opd.DPTRL:
            return il.reg(2, DPTRL)

        case Opd.BIT:
            byte_val = read_const_address(il, op.const_address(data, addr, var), var)
            bit_val = il.const(1, op.bit(data, addr))
            return il.test_bit(1, byte_val, bit_val)

        case Opd.COMPLEMENTED_BIT:
            byte_val = read_const_address(il, op.const_address(data, addr, var), var)
            bit_val = il.const(1, op.bit(data, addr))
            return cmp_zero(il, il.test_bit(1, byte_val, bit_val))

        case Opd.CARRY_FLAG:
            return il.flag(C)

        case Opd.AT_A_PLUS_DPTR | Opd.AT_A_PLUS_PC | Opd.AT_DPTR | Opd.AT_R0 | Opd.AT_R1 | Opd.AT_XDATA_R0 | Opd.AT_XDATA_R1:
            addr = calculate_dyn_address(il, op, addr, var)
            return il.load(1, addr)

        case _:
            raise ValueError(f'unknown read operand {op}')

def write_operand(il: LowLevelILFunction, op: Opd, data: bytes, addr: int, var: Variant, val: ExpressionIndex) -> ExpressionIndex:
    match op:
        case Opd.A | Opd.R0 | Opd.R1 | Opd.R2 | Opd.R3 | Opd.R4 | Opd.R5 | Opd.R6 | Opd.R7:
            return il.set_reg(1, RegisterName(op.name), val)

        case Opd.DPTR:
            return il.set_reg(var.xdata_size(), DPTR, val)

        case Opd.DPTRL:
            return il.set_reg(2, DPTRL, val)

        case Opd.DIRECT1 | Opd.DIRECT2:
            return write_const_address(il, op.const_address(data, addr, var), var, val)

        case Opd.BIT:
            const_addr = op.const_address(data, addr, var)
            orig_val = read_const_address(il, const_addr, var)
            bit = op.bit(data, addr)
            mask = il.const(1, 0xff ^ 1 << bit)
            masked_original = il.and_expr(1, orig_val, mask)
            bit_val = il.const(1, op.bit(data, addr))
            shifted_val = il.shift_left(1, val, bit_val)
            new_val = il.or_expr(1, shifted_val, masked_original)
            return write_const_address(il, const_addr, var, new_val)
        
        case Opd.CARRY_FLAG:
            return il.set_flag(C, val)        
        
        case Opd.AT_A_PLUS_DPTR | Opd.AT_A_PLUS_PC | Opd.AT_DPTR | Opd.AT_R0 | Opd.AT_R1 | Opd.AT_XDATA_R0 | Opd.AT_XDATA_R1:
            addr = calculate_dyn_address(il, op, addr, var)
            return il.store(1, addr, val)
        case _:
            raise ValueError
        

def modify_operand(il: LowLevelILFunction, op: Opd, data: bytes, addr: int, var: Variant, f) -> ExpressionIndex:
    val = read_operand(il, op, data, addr, var)
    res = f(val)
    return write_operand(il, op, data, addr, var, res)

def with_jump_dests_as_labels(il: LowLevelILFunction, var: Variant, addresses: list[int], f):
    arch = Architecture[var.arch_name()]
    unresolved_branches = []
    labels = []
    for address in addresses:
        label = il.get_label_for_address(arch, address)
        if not label:
            label = LowLevelILLabel()
            unresolved_branches.append((label, address))
        labels.append(label)
    
    il.append(f(*labels))

    for (label, address) in unresolved_branches:
        il.mark_label(label)
        il.jump(il.const_pointer(internal_addr_size, address))

def cond_jump(il: LowLevelILFunction, inst: Instruction, data: bytes, addr: int, var: Variant):
    match inst.operation:
        case Op.JC | Op.JNC:
            cond = il.flag(C)
            negate = inst.operation == Op.JNC
        case Op.JB | Op.JBC | Op.JNB:
            cond = read_operand(il, inst.operands[0], data, addr, var)
            negate = inst.operation == Op.JNB
        case Op.JZ | Op.JNZ:
            cond = il.compare_equal(1, il.reg(1, A), il.const(1, 0))
            negate = inst.operation == Op.JNZ
        case _:
            raise ValueError
    succ = inst.operands[-1].const_address(data, addr, var)
    fail = addr

    if negate:
        cond = cmp_zero(il, cond)

    if inst.operation == Op.JBC:
        temp = LLIL_TEMP(1)
        il.append(il.set_reg(1, temp, cond))
        cond = il.reg(1, temp)
        il.append(write_operand(il, inst.operands[0], data, addr, var, il.const(1, 0)))

    with_jump_dests_as_labels(il, var, [succ, fail], lambda succ, fail: il.if_expr(cond, succ, fail))


def lift_instruction(il: LowLevelILFunction, inst: Instruction, data: bytes, addr: int, var: Variant):
    (data, addr) = inst.data_addr(data, addr, var)
    args = inst.operands
    modify = lambda f: modify_operand(il, args[0], data, addr, var, f)
    read = lambda i: read_operand(il, args[i], data, addr, var)
    write = lambda i, val: write_operand(il, args[i], data, addr, var, val)
    match inst.operation:
        case Op.NOP:
            il.append(il.nop())
        case Op.AJMP | Op.LJMP:
            target = il.const_pointer(internal_addr_size, code_addr(inst.operands[-1].const_address(data, addr, var)))
            il.append(il.jump(target))
        case Op.RR:
            il.append(modify(lambda x: il.rotate_right(1, x, il.const(1, 1))))
        case Op.INC:
            il.append(modify(lambda x: il.add(1, x, il.const(1, 1))))
        case Op.DEC:
            il.append(modify(lambda x: il.sub(1, x, il.const(1, 1))))
        case Op.ACALL | Op.LCALL:
            target = il.const_pointer(internal_addr_size, code_addr(inst.operands[-1].const_address(data, addr, var)))
            il.append(il.call(target))
        case Op.RRC:
            tmp = LLIL_TEMP(0)
            lhs = read(0)
            carry = il.test_bit(1, lhs, il.const(1, 0))
            il.append(il.set_reg(1, tmp, carry))
            il.append(write(0, il.rotate_right_carry(1, lhs, il.const(1, 1), il.flag(C))))
            il.append(il.set_flag(C, il.reg(1, tmp)))
        case Op.MOV | Op.MOVC | Op.MOVX:
            val = read(1)
            il.append(write_operand(il, args[0], data, addr, var, val))
        case Op.ANL:
            rhs = read(1)
            il.append(modify(lambda x: il.and_expr(1, x, rhs)))
        case Op.ORL:
            rhs = read(1)
            il.append(modify(lambda x: il.or_expr(1, x, rhs)))
        case Op.XRL:
            rhs = read(1)
            il.append(modify(lambda x: il.xor_expr(1, x, rhs)))
        case Op.CLR:
            il.append(write(0, il.const(0, 0)))
        case Op.CPL:
            if args[0].is_bit():
                il.append(modify(lambda x: cmp_zero(il, x)))
            else:
                il.append(modify(lambda x: il.not_expr(1, x)))
        case Op.SWAP:
            four = il.const(1, 4)
            il.append(modify(lambda x: il.or_expr(1, il.shift_left(1, x, four), il.arith_shift_right(1, x, four))))
        case Op.MUL:
            ab = LLIL_TEMP(0)
            il.append(il.set_reg(2, ab, il.mult_double_prec_unsigned(1, il.reg(1, A), il.reg(1, B))))
            ab = il.reg(2, ab)
            a = il.low_part(1, ab)
            b = il.arith_shift_right(1, ab, il.const(1, 8))
            il.append(il.set_reg(1, A, a))
            il.append(il.set_reg(1, B, b))
            il.append(il.set_flag(OV, il.compare_unsigned_greater_equal(1, ab, il.const(2, 0x100))))
            il.append(il.set_flag(C, il.const(1, 0)))
        case Op.DIV:
            a = LLIL_TEMP(0)
            il.append(il.set_reg(1, a, il.reg(1, A)))
            a = il.reg(1, a)
            il.append(il.set_flag(OV, cmp_zero(il, il.reg(1, B))))
            il.append(il.set_reg(1, A, il.div_unsigned(1, a, il.reg(1, B))))
            il.append(il.set_reg(1, B, il.mod_unsigned(1, a, il.reg(1, B))))
            il.append(il.set_flag(C, il.const(1, 0)))
        case Op.DA:
            # not even going to bother with this one
            il.append(il.unimplemented())
        case Op.PUSH:
            val = read(0)
            il.append(il.push(1, val))
        case Op.POP:
            val = il.pop(1)
            il.append(write(0, val))
        case Op.SETB:
            il.append(write(0, il.const(1, 1)))
        case Op.SJMP:
            target = args[-1].const_address(data, addr, var)
            with_jump_dests_as_labels(il, var, [target], lambda target: il.append(il.goto(target)))
        case Op.SUBB:
            lhs = read(0)
            rhs = read(1)
            tmp = LLIL_TEMP(0)
            carry = il.or_expr(1,
                il.compare_unsigned_less_than(1, lhs, rhs),
                il.and_expr(1,
                    il.compare_equal(1, lhs, rhs),
                    il.flag(C)))
            il.append(il.set_reg(1, tmp, carry))
            il.append(write(0, il.sub_borrow(1, lhs, rhs, il.flag(C))))
            il.append(il.set_flag(C, il.reg(1, tmp)))
        case Op.ADD:
            rhs = read(1)
            il.append(modify(lambda x: il.add(1, x, rhs, flags='*')))
        case Op.ADDC:
            rhs = read(1)
            il.append(modify(lambda x: il.add_carry(1, x, rhs, il.flag(C), flags='*')))
        case Op.RL:
            il.append(modify(lambda x: il.rotate_left(1, x, il.const(1, 1))))
        case Op.RLC:
            tmp = LLIL_TEMP(0)
            lhs = read(0)
            carry = il.test_bit(1, lhs, il.const(1, 7))
            il.append(il.set_reg(1, tmp, carry))
            il.append(write(0, il.rotate_left_carry(1, lhs, il.const(1, 1), il.flag(C))))
            il.append(il.set_flag(C, il.reg(1, tmp)))
        case Op.XCH:
            lhs = LLIL_TEMP(0)
            il.append(il.set_reg(1, lhs, read(0)))
            il.append(write(0, read(1)))
            il.append(write(1, il.reg(1, lhs)))
        case Op.XCHD:
            rhs = read(1)
            lhs = LLIL_TEMP(0)
            il.append(il.set_reg(1, lhs, read(0)))
            lhs = il.reg(1, lhs)
            lhs_lo = il.and_expr(1, lhs, il.const(1, 0x0f))
            lhs_hi = il.and_expr(1, lhs, il.const(1, 0xf0))
            rhs_lo = il.and_expr(1, rhs, il.const(1, 0x0f))
            rhs_hi = il.and_expr(1, rhs, il.const(1, 0xf0))
            new_lhs = il.or_expr(1, rhs_lo, lhs_hi)
            new_rhs = il.or_expr(1, lhs_lo, rhs_hi)
            il.append(write(0, new_lhs))
            il.append(write(1, new_rhs))
        case Op.RET | Op.RETI:
            il.append(il.ret(il.pop(var.code_size())))
        case Op.JC | Op.JNC | Op.JB | Op.JBC | Op.JNB | Op.JZ | Op.JNZ:
            cond_jump(il, inst, data, addr, var)
        case Op.JMP:
            addr = calculate_dyn_address(il, args[-1], addr, var)
            il.append(il.jump(addr))
        case Op.DJNZ:
            il.append(modify(lambda x: il.sub(1, x, il.const(1, 1))))
            lhs = read(0)
            not_zero = il.compare_not_equal(1, lhs, il.const(1, 0))
            not_zero_branch = inst.operands[-1].const_address(data, addr, var)
            zero_branch = addr
            with_jump_dests_as_labels(il, var, [not_zero_branch, zero_branch],
                        lambda not_zero_branch, zero_branch: il.if_expr(not_zero, not_zero_branch, zero_branch))
        case Op.CJNE:
            lhs = read(0)
            rhs = read(1)
            not_eq = il.compare_not_equal(1, lhs, rhs)
            il.append(il.set_flag(C, il.compare_unsigned_less_than(1, rhs, lhs)))
            not_zero_branch = inst.operands[-1].const_address(data, addr, var)
            zero_branch = addr
            with_jump_dests_as_labels(il, var, [not_zero_branch, zero_branch],
                        lambda not_eq_branch, eq_branch: il.if_expr(not_eq, not_eq_branch, eq_branch))
    
    return inst.length