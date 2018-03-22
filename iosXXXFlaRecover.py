import idautils
import idc
from llvmIOSThumb2FlaRecover import LLVMIOSThumb2FlaRecover
from singleton import singleton


@singleton
class IOSXXXFlaRecover(LLVMIOSThumb2FlaRecover):
    def __init__(self, data, offset):
        LLVMIOSThumb2FlaRecover.__init__(self, data, offset)

    def get_relevant_infos(self, relevant):
        find_start = False
        infos = {}
        h = idautils.Heads(relevant.startEA, relevant.endEA)
        last = None
        for i in h:
            mnem = idc.GetMnem(i)
            if (mnem == "tst.w") or (mnem == "TST.W"):
                find_start = True
                infos["fix_start"] = (i + idc.get_item_size(i))
                # infos["fix_start_inst_len"] =
            elif find_start == True and (mnem.startswith("IT ") or mnem.startswith("it ")):
                infos["fix_end"] = (i + idc.get_item_size(i) + idc.get_item_size(i + idc.get_item_size(i)))
                infos["conf_type"] = mnem[3:]
                find_start = False

            last = i
        infos["last"] = (last)

        return infos

    def fix_prologue(self, parent, childs, flaFunc):
        # print "111"
        self.fill_thumb_b_inst_by_addr(flaFunc.main_dispatcher.startEA, flaFunc.main_dispatcher.startEA, childs[0])
        return

    def fix_direct_branch(self, parent, childs, flaFunc):
        # print "222"
        infos = self.get_relevant_infos(parent)
        self.fill_thumb_b_inst_by_addr(infos["last"], infos["last"], childs[0])
        return

    def fix_conf_branch(self, parent, childs, flaFunc):
        # print "333"
        infos = self.get_relevant_infos(parent)
        self.fill_nop(infos["fix_start"], infos["fix_end"])
        move_inst_len = infos["last"] - infos["fix_end"]
        self.mov_inst(infos["fix_start"], infos["fix_end"], move_inst_len)
        index = infos["fix_start"] + move_inst_len
        self.fill_thumb2_bcc_inst_by_addr('bne.w', index, index, childs[0])
        index = index + 4
        self.fill_nop(index, infos["last"])
        self.fill_thumb_b_inst_by_addr(infos["last"], infos["last"], childs[1])
        return