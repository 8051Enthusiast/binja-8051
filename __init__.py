from binaryninja import FlagRole, LowLevelILFlagCondition
from binaryninja.architecture import Architecture, RegisterInfo
from . import instructions
from . import lift

class I8051(Architecture):
    name = '8051'
    address_size = 2
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 3
    regs = {
        'A': RegisterInfo('A', 1),
        'B': RegisterInfo('B', 1),
        'DPTR': RegisterInfo('DPTR', 2),
        'DPL': RegisterInfo('DPTR', 1, 0),
        'DPH': RegisterInfo('DPTR', 1, 1),
        'SP': RegisterInfo('SP', 1),
        'PSW': RegisterInfo('PSW', 1),
        'R0': RegisterInfo('R0', 1),
        'R1': RegisterInfo('R1', 1),
        'R2': RegisterInfo('R2', 1),
        'R3': RegisterInfo('R3', 1),
        'R4': RegisterInfo('R4', 1),
        'R5': RegisterInfo('R5', 1),
        'R6': RegisterInfo('R6', 1),
        'R7': RegisterInfo('R7', 1)
    }
    stack_pointer = 'SP'
    flags = ['C', 'AC', 'OV']
    flag_roles = {
        'C': FlagRole.CarryFlagRole,
        'AC': FlagRole.HalfCarryFlagRole,
        'OV': FlagRole.OverflowFlagRole,
    }

    flag_write_types = ['', '*', 'ov', 'c']
    flags_written_by_flag_write_type = {
        '': [],
        '*': ['C', 'AC', 'OV'],
        'ov': ['OV'],
        'c': ['C'],
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGE
    }

    def get_instruction_info(self, data, addr):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        info = instr.instruction_info(data, addr)
        return info

    def get_instruction_text(self, data, addr):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        return instr.instruction_text(data, addr), instr.length

    def get_instruction_low_level_il(self, data, addr, il):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        return lift.lift_instruction(il, instr, data, addr)


I8051.register()

