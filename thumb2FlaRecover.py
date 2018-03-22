import struct

from flaRecover import FlaRecover
from thumb2Util import Thumb2Util


class Thumb2FlaRecover(FlaRecover):
    def __init__(self, data, offset):
        FlaRecover.__init__(self, data, offset)
        self.instUtil = Thumb2Util()
        # self.thumb2Util = self.instUtil

    def fill_thumb_b_inst_by_offset(self, start, offset):
        jmp_offset = self.instUtil.fill_thumb_b_inst_by_offset(start, offset)
        for i in range(2):
            self.origin_data[start + i - self.base_offset] = jmp_offset[i]

    def fill_thumb_b_inst_by_addr(self, start, currentEA, destEA):
        offset = self.instUtil.get_thumb_jmp_offset(currentEA, destEA)
        self.fill_thumb_b_inst_by_offset(start, offset)

    def fill_thumb2_b_inst_by_offset(self, start, offset):
        jmp_offset1, jmp_offset2 = self.instUtil.fill_thumb2_b_inst_by_offset(start, offset)

        #high
        for i in range(2):
            self.origin_data[start + i - self.base_offset] = jmp_offset1[i]
        #low
        for i in range(2):
            self.origin_data[start + 2 + i - self.base_offset] = jmp_offset2[i]

    def fill_thumb2_b_inst_by_addr(self, start, currentEA, destEA):
        offset = self.instUtil.get_thumb_jmp_offset(currentEA, destEA)
        self.fill_thumb2_b_inst_by_offset(start, offset)

    def mov_inst(self, dest, src, len):
        if dest == src:
            return

        for i in range(len):
            if dest < src:
                self.origin_data[dest + i - self.base_offset] = self.origin_data[src + i - self.base_offset]
            else:
                self.origin_data[dest + (len - 1 - i) - self.base_offset] = self.origin_data[src + (len - 1 - i) - self.base_offset]

    def fill_thumb_bcc_inst_by_offset(self, bcc_type, start, offset):
        jmp_offset = self.instUtil.fill_thumb_bcc_inst_by_offset(bcc_type, start, offset)
        for i in range(2):
            self.origin_data[start + i - self.base_offset] = jmp_offset[i]

    def fill_thumb_bcc_inst_by_addr(self, bcc_type, start, currentEA, destEA):
        offset = self.instUtil.get_thumb_jmp_offset(currentEA, destEA)
        self.fill_thumb_bcc_inst_by_offset(bcc_type, start, offset)

    def fill_thumb2_bcc_inst_by_offset(self, bcc_type, start, offset):
        jmp_offset1, jmp_offset2 = self.instUtil.fill_thumb2_bcc_inst_by_offset(bcc_type, start, offset)

        #high
        for i in range(2):
            self.origin_data[start + i - self.base_offset] = jmp_offset1[i]
        #low
        for i in range(2):
            self.origin_data[start + 2 + i - self.base_offset] = jmp_offset2[i]

    def fill_thumb2_bcc_inst_by_addr(self, bcc_type, start, currentEA, destEA):
        offset = self.instUtil.get_thumb_jmp_offset(currentEA, destEA)
        self.fill_thumb2_bcc_inst_by_offset(bcc_type, start, offset)