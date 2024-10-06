from dataclasses import dataclass

from binaryninja import RegisterInfo, RegisterName

from .defs import *

addr_mapped_registers = {
    (imem_base + 0x00): R0,
    (imem_base + 0x01): R1,
    (imem_base + 0x02): R2,
    (imem_base + 0x03): R3,
    (imem_base + 0x04): R4,
    (imem_base + 0x05): R5,
    (imem_base + 0x06): R6,
    (imem_base + 0x07): R7,
    (sfr_base + 0x81): SP,
    (sfr_base + 0x82): DPL,
    (sfr_base + 0x83): DPH,
    (sfr_base + 0xd0): PSW,
    (sfr_base + 0xe0): A,
    (sfr_base + 0xf0): B,
}

DPX_ADDRESS = sfr_base + 0x93

# information for the kind of 8051 derivative
@dataclass
class Variation:
    extended_xdata: bool
    bank_size: int | None

    def xdata_size(self) -> int:
        return 3 if self.extended_xdata else 2 

    def code_size(self):
        return 3 if self.bank_size else 2
    
    def arch_name(self) -> str:
        name = "8051"
        if self.extended_xdata:
            name += "-xdata24"
        if self.bank_size:
            name += f"-bank{self.bank_size >> 10}k"
        return name

    def registers(self) -> dict[RegisterName, RegisterInfo]:
        regs = {
            A: RegisterInfo(A, 1),
            B: RegisterInfo(B, 1),
            SP: RegisterInfo(SP, 1),
            PSW: RegisterInfo(PSW, 1),
            R0: RegisterInfo(R0, 1),
            R1: RegisterInfo(R1, 1),
            R2: RegisterInfo(R2, 1),
            R3: RegisterInfo(R3, 1),
            R4: RegisterInfo(R4, 1),
            R5: RegisterInfo(R5, 1),
            R6: RegisterInfo(R6, 1),
            R7: RegisterInfo(R7, 1)
        }
        if self.extended_xdata:
            regs |= {
                DPTR: RegisterInfo(DPTR, 3),
                DPL: RegisterInfo(DPTR, 1, 0),
                DPH: RegisterInfo(DPTR, 1, 1),
                DPTRL: RegisterInfo(DPTR, 2, 0),
                DPX: RegisterInfo(DPTR, 1, 2),
            }
        else:
            regs |= {
                DPTR: RegisterInfo(DPTR, 2),
                DPTRL: RegisterInfo(DPTR, 2, 0),
                DPL: RegisterInfo(DPTR, 1, 0),
                DPH: RegisterInfo(DPTR, 1, 1),
            }

        return regs

    def register_at_address(self, addr: int) -> RegisterName | None:
        if addr == DPX_ADDRESS and self.extended_xdata:
            return DPX
        return addr_mapped_registers.get(addr)

    def norm_bank_size(self) -> int:
        if not self.bank_size:
            return 0x10000
        return self.bank_size

    def bank_base(self) -> int:
        return 0x10000 - self.norm_bank_size()

    def bank_and_local_addr(self, addr: int) -> tuple[int, int]:
        base = self.bank_base()
        size = self.norm_bank_size()
        bank = max(0, (addr - base) // size)
        addr = addr - bank * size
        return (bank, addr)
    
    def addr_with_bank(self, addr: int, bank: int) -> int:
        base = self.bank_base()
        if addr < base:
            return addr
        return bank * self.norm_bank_size() + addr
    
    def add_code_addr(self, origin: int, offset: int) -> int:
        (orig_bank, orig_addr) = self.bank_and_local_addr(origin)
        new_addr = (orig_addr + offset) & 0xffff
        return self.addr_with_bank(new_addr, orig_bank)

    def based_addr(self, base: int, local_addr: int) -> int:
        (bank, _) = self.bank_and_local_addr(base)
        return self.addr_with_bank(local_addr, bank)