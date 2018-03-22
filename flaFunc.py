import claripy
import struct

import define
import idaapi
import idautils
import idc
import simuvex
import angr
import pyvex

#use ida cfg
from baseFlaFunc import BaseFlaFunc
from define import flaFunc_type_common


class FlaFunc(BaseFlaFunc):
    def __init__(self):
        BaseFlaFunc.__init__(self)
        self.func = None
        #block object
        self.prologue = None
        #block object
        self.main_dispatcher = None
        #block object
        self.pre_dispatcher = None
        #block object
        self.retn = None
        #block object
        self.relevant_blocks = list()
        #block object
        self.nop_blocks = list()
        #string
        self.func_name = None
        #block object
        self.blocks = None
        #int
        self.start = None
        self.relevants_flow = None

    def find_first_succs_block(self, b):
        for succ in b.succs():
            return succ

        return None

    def find_prologue_block(self):
        for b in self.blocks:
            if b.startEA == self.start:
                # prologue_start = "{0:x}".format(b.startEA)
                # print "[FlaFunc::find_prologue_block]find prologue: %s" % prologue_start
                self.prologue = b
                return True

        self.prologue = None
        return False

    def find_main_dispatcher_block(self):
        b = self.prologue
        while(True):
            succs_list = list(b.succs())
            if len(succs_list) > 1:
                self.main_dispatcher = b
                return True

            preds_list = list(b.preds())
            if len(preds_list) > 1:
                self.main_dispatcher = b
                return True

            # print "block: %x, succs: %d, preds: %d" % (b.startEA, len(succs_list), len(preds_list))

            b = succs_list[0]

        # for b in self.prologue.succs():
        #     # main_dispatcher_start = "{0:x}".format(b.startEA)
        #     # print "[FlaFunc::find_main_dispatcher_block]find main_dispatcher: %s" % main_dispatcher_start
        #     self.main_dispatcher = b
        #     return True

        self.main_dispatcher = None
        return False

    def find_retn_predispatcher_block(self):
        find_retn = False
        find_pre = False
        retn = None
        pre_dispatcher = None
        for b in self.blocks:
            if len(list(b.succs())) == 0:
                # retn_start = "{0:x}".format(b.startEA)
                # print "[FlaFunc::find_retn_predispatcher_block]find retn: %s" % retn_start
                retn = b
                find_retn = True
            elif b.startEA != self.prologue.startEA and None != self.find_first_succs_block(b) and self.find_first_succs_block(b).startEA == self.main_dispatcher.startEA:
                # pre_dispatcher_start = "{0:x}".format(b.startEA)
                # print "[FlaFunc::find_retn_predispatcher_block]find pre_dispatcher: %s" % pre_dispatcher_start
                pre_dispatcher = b
                find_pre = True

            if find_retn == True and find_pre == True:
                break
        self.retn = retn
        self.pre_dispatcher = pre_dispatcher
        return True

    def get_relevant_nop_blocks(self):
        # relevant_blocks = []
        # nop_blocks = []
        for b in self.blocks:
            h = idautils.Heads(b.startEA, b.endEA)
            # print "block %08x - heads count %d" % (b.startEA, len(list(h)))
            if self.find_first_succs_block(b) != None and self.find_first_succs_block(b).startEA == self.pre_dispatcher.startEA and len(list(h)) > 1:
                self.relevant_blocks.append(b)
            elif b.startEA != self.prologue.startEA and b.startEA != self.retn.startEA:
                self.nop_blocks.append(b)

        # print "[FlaFunc::get_relevant_nop_blocks]relevant_blocks count: %d" % len(self.relevant_blocks)
        # print "[FlaFunc::get_relevant_nop_blocks]nop_blocks count: %d" % len(self.nop_blocks)
        return True


    def get_all_type_blocks(self):
        self.blocks = idaapi.FlowChart(self.func, flags=idaapi.FC_PREDS)
        self.find_prologue_block()
        self.find_main_dispatcher_block()
        self.find_retn_predispatcher_block()
        self.get_relevant_nop_blocks()

        return True

    def type(self):
        return flaFunc_type_common

    def load(self, param):
        addr = param[define.flaFunc_param_addr]
        self.func = idaapi.get_func(addr)
        self.func_name = idc.get_func_name(addr)
        self.start = self.func.start_ea
        self.get_all_type_blocks()

        print '\n[FlaFunc]function name: %s' % self.func_name
        print '[FlaFunc]*******************relevant blocks************************'
        print '[FlaFunc]prologue:%#x, %#x' % (self.prologue.startEA, self.prologue.endEA)
        print '[FlaFunc]main_dispatcher:%#x, %#x' % (self.main_dispatcher.startEA, self.main_dispatcher.endEA)
        print '[FlaFunc]pre_dispatcher:%#x, %#x' % (self.pre_dispatcher.startEA, self.pre_dispatcher.endEA)
        print '[FlaFunc]retn:%#x, %#x' % (self.retn.startEA, self.retn.endEA)
        print '[FlaFunc]relevant_blocks:', "[count: " + str(len(self.relevant_blocks)) + "]", [str(hex(b.startEA)) + "-" + str(hex(b.endEA)) for b in self.relevant_blocks]
