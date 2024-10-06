from binaryninja import FlagRole, LowLevelILFlagCondition
from binaryninja.architecture import Architecture, RegisterInfo
from . import instructions
from . import lift
from . import variation
from . import callconv
from .defs import *

class I8051Core(Architecture):
    name: str
    i8051_variation: variation.Variation
    default_int_size = 1
    instr_alignment = 1
    max_instr_length = 3
    stack_pointer = 'SP'
    flags = [C, AC, OV]
    flag_roles = {
        C: FlagRole.CarryFlagRole,
        AC: FlagRole.HalfCarryFlagRole,
        OV: FlagRole.OverflowFlagRole,
    }

    flag_write_types = ['', '*', 'ov', 'c']
    flags_written_by_flag_write_type = {
        '': [],
        '*': ['C', 'AC', 'OV'],
        'ov': ['OV'],
        'c': ['C'],
    }

    def get_instruction_info(self, data, addr):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        info = instr.instruction_info(data, addr, self.i8051_variation)
        return info

    def get_instruction_text(self, data, addr):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        return instr.instruction_text(data, addr, self.i8051_variation), instr.length

    def get_instruction_low_level_il(self, data, addr, il):
        instr = instructions.get_instr(data, addr)
        if not instr:
            return None
        return lift.lift_instruction(il, instr, data, addr, self.i8051_variation)

class I8051(I8051Core):
    i8051_variation = variation.Variation(False, None)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()

class I8051Bank16K(I8051Core):
    i8051_variation = variation.Variation(False, 0x4000)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()

class I8051Bank32K(I8051Core):
    i8051_variation = variation.Variation(False, 0x8000)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()

class I8051XData24(I8051Core):
    i8051_variation = variation.Variation(True, None)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()

class I8051XData24Bank16K(I8051Core):
    i8051_variation = variation.Variation(True, 0x4000)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()
    
class I8051XData24Bank32K(I8051Core):
    i8051_variation = variation.Variation(True, 0x8000)
    name = i8051_variation.arch_name()
    address_size = i8051_variation.code_size()
    regs = i8051_variation.registers()

def register(arch: type[I8051Core]):
    arch.register()
    arch_instance = Architecture[arch.name]
    iar = callconv.IARCC(arch_instance, "IAR")
    iar_banked = callconv.IARCC(arch_instance, "IAR-banked")
    arch_instance.register_calling_convention(callconv.KeilCC(arch_instance, "default"))
    arch_instance.register_calling_convention(iar)
    arch_instance.register_calling_convention(iar_banked)

register(I8051)
register(I8051Bank16K)
register(I8051Bank32K)
register(I8051XData24)
register(I8051XData24Bank16K)
register(I8051XData24Bank32K)