import define
from InstUtl import InstUtil


class FlaRecover:
    def __init__(self, data, offset):
        # self.filename = None
        self.base_offset = offset
        self.origin_data = data
        # self.opcode = None
        self.instUtil = None

    def fill_nop(self, start, end):
        if start >= end:
            return
        nop_code = self.instUtil.get_nop_code()
        if nop_code == None or nop_code == "":
            return
        index = 0
        for i in range(start, end):
            self.origin_data[i - self.base_offset] = nop_code[index % (len(nop_code))]
            index = index + 1

    #must be override
    def fix_prologue(self, parent, childs, flaFunc):
        return

    #must be override
    def fix_direct_branch(self, parent, childs, flaFunc):
        return

    #must be override
    def fix_conf_branch(self, parent, childs, flaFunc):
        return

    def fix_fla_func_common(self, flaFunc):
        flow = flaFunc.relevants_flow
        flow.pop(flaFunc.retn)
        for nop_block in flaFunc.nop_blocks:
            self.fill_nop(nop_block.startEA, nop_block.endEA)
        for (parent, childs) in flow.items():
            if parent.startEA == flaFunc.prologue.startEA:
                self.fix_prologue(parent, childs, flaFunc)
            elif len(childs) == 1:
                self.fix_direct_branch(parent, childs, flaFunc)
            else:
                self.fix_conf_branch(parent, childs, flaFunc)

    def fix_fla_func(self, flaFunc):
        if flaFunc.type() == define.flaFunc_type_common:
            self.fix_fla_func_common(flaFunc)

    def fix_fla_funcs(self, flaFuncs):
        for flaFunc in flaFuncs:
            self.fix_fla_func(flaFunc)
