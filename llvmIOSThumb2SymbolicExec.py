import idautils
import idc
from singleton import singleton
from symbolicExec import SymbolicExec

@singleton
class LLVMIOSThumb2SymbolicExec(SymbolicExec):
    def __init__(self):
        SymbolicExec.__init__(self)

    def fix_addr_ida_2_angr(self, addr):
        return (addr | 0x1)

    def fix_addr_angr_2_ida(self, addr):
        if (addr & 0x1) == 1:
            return (addr - 1)

        return addr

    def get_all_call_addr(self, relevant):
        addrs = {}
        h = idautils.Heads(relevant.startEA, relevant.endEA)
        for i in h:
            mnem = idc.GetMnem(i)
            if (mnem == "bl" or mnem == "blx") or (mnem == "BL" or mnem == "BLX"):
                addrs[i] = idc.get_item_size(i)
                # addr = {}
                # addr[i] = idc.get_item_size(i)
                # addrs.append(addr)

        return addrs

