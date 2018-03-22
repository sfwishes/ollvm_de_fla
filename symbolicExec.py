import claripy
import struct

import idaapi
import idautils
import idc
import simuvex
import angr
import pyvex
from sets import Set
import define

#may not suitable with some case, modify it by yourself

g_proj = None
g_modify_value = None
g_has_branches = False

def retn_procedure(state):
    global g_proj
    # print "retn_procedure called"
    print state.regs.ip
    ip = state.se.any_int(state.regs.ip)
    g_proj.unhook(ip)
    return

def statement_inspect(state):
    global g_modify_value
    global g_has_branches
    expressions = state.scratch.irsb.statements[state.inspect.statement].expressions
    # print expressions
    if len(expressions) > 0:
        expression = expressions[0]
        if isinstance(expression, pyvex.expr.ITE):
            if isinstance(expression.iftrue, pyvex.expr.Const) and isinstance(expression.iffalse, pyvex.expr.Const):
                iftrue = int(str(expression.iftrue), 16)
                iffalse = int(str(expression.iffalse), 16)
                if iftrue >= 0x1000000 and iffalse >= 0x1000000:
                    state.scratch.temps[expressions[0].cond.tmp] = g_modify_value
                    state.inspect._breakpoints['statement'] = []
                    g_has_branches = True
                    # print "reached"

#symbolic exec by angr, must be single instance
class SymbolicExec():
    def __init__(self):
        self.filename = None
        self.proj = None

    #override this method according diffrent instructions
    def fix_addr_ida_2_angr(self, addr):
        return addr
    #override this method according diffrent instructions
    def fix_addr_angr_2_ida(self, addr):
        return addr

    def inspect(self, state, inspect):
        if inspect:
            state.inspect.b('statement', when=simuvex.BP_BEFORE, action=statement_inspect)

    #must be override
    def get_all_call_addr(self, relevant):
        addrs = {}
        # h = idautils.Heads(startEA, endEA)
        # for i in h:
        #     mnem = idc.GetMnem(i)
        #     if (mnem == "bl" or mnem == "blx") or (mnem == "BL" or mnem == "BLX"):
        #         addrs[i] = idc.get_item_size(i)
        #         # addr = {}
        #         # addr[i] = idc.get_item_size(i)
        #         # addrs.append(addr)

        return addrs


    def symbolic_execution(self, start_addr, relevants_head, hook_addrs, modify=None, inspect=False):
        global g_modify_value
        for (hook_addr, len) in hook_addrs.items():
            self.proj.hook(self.fix_addr_ida_2_angr(hook_addr), retn_procedure, length=len)
        if modify != None:
            g_modify_value = modify
        state = self.proj.factory.blank_state(addr=self.fix_addr_ida_2_angr(start_addr), remove_options={simuvex.o.LAZY_SOLVES})
        self.inspect(state, inspect)
        p = self.proj.factory.path(state)
        successors = p.step()
        while (self.fix_addr_angr_2_ida(successors[0].addr)) not in relevants_head:
            p = successors[0]
            successors = p.step()
        return successors[0].addr

    def run_flaFunc_common(self, flaFunc):
        global g_has_branches
        relevants = flaFunc.relevant_blocks
        relevants.append(flaFunc.prologue)
        relevants_without_retn = list(relevants)
        relevants.append(flaFunc.retn)
        flow = {}

        relevant_heads = list()
        for parent in relevants:
            relevant_heads.append(parent.startEA)
            flow[parent] = []
        for relevant in relevants_without_retn:
            call_addrs = self.get_all_call_addr(relevant)

            g_has_branches = False
            flow[relevant].append(self.symbolic_execution(relevant.startEA, relevant_heads, call_addrs, claripy.BVV(1, 1), True))
            if g_has_branches:
                flow[relevant].append(self.symbolic_execution(relevant.startEA, relevant_heads, call_addrs, claripy.BVV(0, 1), True))

        print '\n************************flow******************************'
        for (k, v) in flow.items():
            print '%#x:' % k.startEA, [hex(child) for child in v]

        flaFunc.relevants_flow = flow

    def run_flaFunc(self, flaFunc):
        if flaFunc.type() == define.flaFunc_type_common:
            self.run_flaFunc_common(flaFunc)


    def load_file(self):
        self.proj = angr.Project(self.filename,load_options={'auto_load_libs':False, 'main_opts':{'custom_base_addr': 0}})
        if self.proj == None:
            return False
        return True

    def load(self, filename):
        global g_proj
        self.filename = filename
        self.load_file()
        g_proj = self.proj

    def run_flaFuncs(self, funcs):
        for func in funcs:
            self.run_flaFunc(func)