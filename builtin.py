import re
import typing
import json
from itertools import chain

from .arch import REGISTERED_ARCH_NAMES
from .defs import *
from .variant import Variant

from binaryninja import Activity, AnalysisContext, BinaryDataNotification, BinaryReader, BinaryView, LowLevelILCall, LowLevelILConstPtr, LowLevelILInstruction, LowLevelILJump, LowLevelILOperation, NotificationType, Segment

hexpair = re.compile('([0-9a-fA-F]{2})')
def as_regex(pattern: str) -> re.Pattern[bytes]:
    regex = hexpair.sub(r'\\x\1', pattern).replace('??', '.').replace(' ', '')
    return re.compile(bytes(regex, encoding="ascii"), re.ASCII)

PatternTy = list[re.Pattern[bytes]]

def patterns(*str_patterns: str) -> PatternTy:
    return [as_regex(pattern) for pattern in str_patterns]

BDISPATCH_XX = patterns(
    r"d0 83 d0 82 e5 (??) 54 (??) c0 e0 e4 93 c0 e0 74 01 93 c0 e0 74 02 93 54 \2 f5 f0 e5 \1 54 ?? 45 f0 f5 \1 22",
    r"d0 83 d0 82 e5 (??) 54 (??) c0 e0 e4 93 c0 e0 74 01 93 c0 e0 74 02 93 c0 f0 54 \2 f5 f0 e5 \1 54 ?? 45 f0 d0 f0 f5 \1 22",
)
BRET_XX = patterns(r"85 (??) f0 53 f0 ?? d0 e0 45 f0 f5 \1 22")

BDISPATCH_FF = patterns(r"d0 83 d0 82 c0 (??) e4 93 c0 e0 74 01 93 c0 e0 74 02 93 f5 \1 22")
BRET_FF = patterns(r"d0 (??) 22")

def pattern_matches(byte_patterns: PatternTy, input: bytes, bank_pattern_index: int) -> typing.Iterable[tuple[int, int]]:
    return (
        (match.start(), match.group(bank_pattern_index)[0])
            for pattern in byte_patterns
            for match in pattern.finditer(input)
    )

def match_sets(byte_patterns: PatternTy, input: bytes, bank_pattern_index: int) -> tuple[set[int], set[int]]:
    addresses = set()
    bank_sfrs = set()
    for (address, bank_sfr) in pattern_matches(byte_patterns, input, bank_pattern_index):
        addresses.add(address)
        bank_sfrs.add(bank_sfr)
    return (addresses, bank_sfrs)
        
def pattern_dispatch_and_ret_addresses(dispatch: tuple[PatternTy, int], ret: tuple[PatternTy, int],
                                       input: bytes) -> tuple[set[int], set[int]]:
    (dispatch_addresses, dispatch_banks) = match_sets(dispatch[0], input, dispatch[1])
    ret_addresses = {address for (address, ret_bank) in pattern_matches(ret[0], input, ret[1]) if ret_bank in dispatch_banks}
    return (dispatch_addresses, ret_addresses)

def same_value(addresses: set[int], value: str) -> dict[int, str]:
    return {address: value for address in addresses}

class FoundAddresses:
    dispatch: dict[int, str]
    ret: dict[int, str]
    def __init__(self, dispatch: dict[int, str], ret: dict[int, str]):
        self.dispatch = dispatch
        self.ret = ret
    
    def with_offset(self, offset: int):
        self.dispatch = {address + offset: name for (address, name) in self.dispatch.items()}
        self.ret = {address + offset: name for (address, name) in self.ret.items()}
    
    def merge(self, other: "FoundAddresses"):
        self.dispatch.update(other.dispatch)
        self.ret.update(other.ret)

def dispatch_and_ret_addresses(input: bytes) -> FoundAddresses:
    (dispatch_xx, ret_xx) = pattern_dispatch_and_ret_addresses((BDISPATCH_XX, 1),  (BRET_XX, 1), input)
    (dispatch_ff, ret_ff) = pattern_dispatch_and_ret_addresses((BDISPATCH_FF, 1),  (BRET_FF, 1), input)
    dispatch = same_value(dispatch_xx, "?BDISPATCH_XX") | same_value(dispatch_ff, "?BDISPATCH_FF")
    ret = same_value(ret_xx, "?BRET_XX") | same_value(ret_ff, "?BRET_FF")
    return FoundAddresses(dispatch, ret)

def add_segment_functions(bv: BinaryView, start: int, length: int) -> FoundAddresses | None:
    data = bv.read(length, start)
    if not data:
        return
    addresses = dispatch_and_ret_addresses(data)
    for (address, name) in chain(addresses.dispatch.items(), addresses.ret.items()):
        fun = bv.add_function(addr=start + address, plat=None, auto_discovered=True)
        if not fun:
            continue
        fun.name = name
        fun.set_auto_can_return(False)
    addresses.with_offset(start)
    return addresses

def add_functions(bv: BinaryView) -> FoundAddresses:
    found_addresses = FoundAddresses({}, {})
    for segment in bv.segments:
        if not segment.executable:
            continue
        found = add_segment_functions(bv, segment.start, segment.data_length)
        if found:
            found_addresses.merge(found)
    return found_addresses

builtin_detection_name = "analysis.plugins.builtin_detection_8051"

builtin_detection_config = json.dumps({
    "name": builtin_detection_name,
    "title": "Banking Builtin Detection",
    "description": "Analyzes the raw binary for 8051 banking calls",
    "eligibility": {
        "runOncePerSession": True
    }
})

class BinaryModifyNotification(BinaryDataNotification):
    activity: "BuiltinDetectionActivity"
    def __init__(self, activity: "BuiltinDetectionActivity"):
        super(BinaryModifyNotification, self).__init__(NotificationType.BinaryDataUpdates | NotificationType.SegmentUpdates)
        self.received_event = False
        self.activity = activity
    
    def data_inserted(self, view: BinaryView, offset: int, length: int) -> None:
        self.activity.update_positions(view)

    def data_removed(self, view: BinaryView, offset: int, length: int) -> None:
        self.activity.update_positions(view)

    def data_written(self, view: BinaryView, offset: int, length: int) -> None:
        self.activity.update_positions(view)
    
    def segment_added(self, view: BinaryView, segment: Segment) -> None:
        self.activity.update_positions(view)

    def segment_removed(self, view: BinaryView, segment: Segment) -> None:
        self.activity.update_positions(view)

    def segment_updated(self, view: BinaryView, segment: Segment) -> None:
        self.activity.update_positions(view)

class BuiltinDetectionActivity(Activity):
    found_addresses: dict
    def __init__(self):
        super(BuiltinDetectionActivity, self).__init__(builtin_detection_config, action=self.analyze_positions)
        self.found_addresses = dict()

    def analyze_positions(self, ctx: AnalysisContext):
        ctx.view.register_notification(BinaryModifyNotification(self))
        self.update_positions(ctx.view)

    def update_positions(self, view: BinaryView):
        arch = view.arch
        if arch and arch.name in REGISTERED_ARCH_NAMES:
            self.found_addresses[bytes(view.handle)] = add_functions(view)


builtin_detection = BuiltinDetectionActivity()

builtin_replacer_name = "analysis.plugins.builtin_replacer_8051"

builtin_replacer_config = json.dumps({
    "name": builtin_replacer_name,
    "title": "Banking Call Replacer",
    "description": "Resolves calls to the builtin banking functions",
})

class BuiltinReplacerActivity(Activity):
    detector: BuiltinDetectionActivity
    def __init__(self, detector: BuiltinDetectionActivity):
        super(BuiltinReplacerActivity, self).__init__(builtin_replacer_config, action=self.replace_functions)
        self.detector = detector
    
    def found_addresses(self, ctx: AnalysisContext):
        if not bytes(ctx.view.handle) in self.detector.found_addresses:
            return FoundAddresses({}, {})
        return self.detector.found_addresses[bytes(ctx.view.handle)]
    
    def replace_functions(self, ctx: AnalysisContext):
        if not ctx.view.arch or not ctx.view.arch.name in REGISTERED_ARCH_NAMES:
            return
        variant = REGISTERED_ARCH_NAMES[ctx.view.arch.name]
        for block in ctx.lifted_il:
            for instruction in block:
                if self.is_dispatch_call(ctx, instruction):
                    self.replace_dispatch_call(ctx, instruction, variant)
                elif self.is_ret_jump(ctx, instruction):
                    self.replace_ret_jump(ctx, instruction, variant)
    
    def is_dispatch_call(self, ctx: AnalysisContext, instruction: LowLevelILInstruction) -> bool:
        if not isinstance(instruction, LowLevelILCall):
            return False
        target = instruction.dest
        if not isinstance(target, LowLevelILConstPtr):
            return False
        return target.constant in self.found_addresses(ctx).dispatch
    
    def replace_dispatch_call(self, ctx: AnalysisContext, instr: LowLevelILInstruction, variant: Variant):
        # the bytes for the dispatch call are like this:
        # > 0x12 (call)
        # > high ?BDISPATCH
        # > low ?BDISPATCH
        # > low target
        # > high target
        # > bank target
        buf = ctx.view.read(instr.address, 6)
        target = (buf[4] << 8) | buf[3]
        bank = buf[5]
        real_address = variant.addr_with_bank(target, bank)
        ptr = ctx.lifted_il.const_pointer(internal_addr_size, real_address)
        ctx.lifted_il.replace_expr(instr, ctx.lifted_il.tailcall(ptr))
    
    def is_ret_jump(self, ctx: AnalysisContext, instruction: LowLevelILInstruction) -> bool:
        if not isinstance(instruction, LowLevelILJump):
            return False
        target = instruction.dest
        if not isinstance(target, LowLevelILConstPtr):
            return False
        return target.constant in self.found_addresses(ctx).ret
    
    def replace_ret_jump(self, ctx: AnalysisContext, instr: LowLevelILInstruction, variant: Variant):
        il = ctx.lifted_il
        ret = il.ret(il.pop(variant.code_size()))
        il.replace_expr(instr, ret)

builtin_replacer = BuiltinReplacerActivity(builtin_detection)