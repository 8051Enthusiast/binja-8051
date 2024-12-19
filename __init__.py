from binaryninja import Workflow
from . import builtin
from . import arch
from .defs import *

arch.register(arch.I8051)
arch.register(arch.I8051Bank16K)
arch.register(arch.I8051Bank32K)
arch.register(arch.I8051XData24)
arch.register(arch.I8051XData24Bank16K)
arch.register(arch.I8051XData24Bank32K)

workflow = Workflow("core.module.metaAnalysis").clone()
workflow.register_activity(builtin.builtin_detection)
workflow.insert("core.module.basicBlockAnalysis", [builtin.builtin_detection_name])
workflow.register()

workflow = Workflow("core.function.metaAnalysis").clone()
workflow.register_activity(builtin.builtin_replacer)
workflow.insert("core.function.resetIndirectBranchesOnFullUpdate", [builtin.builtin_replacer_name])
workflow.register()