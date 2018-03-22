
#add this table by yourself
import struct

from InstUtl import InstUtil

thumb_opcode = {'nop':['\x00', '\xbf'], 'b':['\xE0'], 'b.w':['\xF0', '\x00', '\xB8', '\x00'], 'beq':['\xD0'], 'bne':['\xD1'], 'beq.w':['\xF0', '\x00', '\x80', '\x00'], 'bne.w':['\xF0', '\x40', '\x80', '\x00']}

class Thumb2Util(InstUtil):
    def __init__(self):
        InstUtil.__init__(self)
        self.opcode = thumb_opcode

    def get_thumb_jmp_offset(self, currentEA, destEA):
        offset = destEA - (currentEA + 4)
        offset = offset / 2
        return offset

    def fill_thumb_b_inst_by_offset(self, start, offset):
        b = bytearray(self.opcode["b"][0])
        inst = (b[0] << 8) | (offset & 0x7ff)
        jmp_offset = struct.pack('<i', inst)
        return jmp_offset

    def fill_thumb2_b_inst_by_offset(self, start, offset):
        thumb2_inst = self.opcode["b.w"]
        sign = 0
        if offset < 0:
            sign = 1
        #high
        b0 = bytearray(thumb2_inst[0])
        b1 = bytearray(thumb2_inst[1])
        high = ((b0[0] | (sign << 2) | ((offset >> 19) & 0x3)) << 8) | ((b1[0] | ((offset >> 11) & 0xff)))
        jmp_offset1 = struct.pack('<i', high)

        #low
        b2 = bytearray(thumb2_inst[2])
        b3 = bytearray(thumb2_inst[3])
        low = ((b2[0] | ((offset >> 8) & 0x7)) << 8) | ((b3[0] | (offset & 0xff)))
        jmp_offset2 = struct.pack('<i', low)

        return jmp_offset1, jmp_offset2

    def fill_thumb_bcc_inst_by_offset(self, bcc_type, start, offset):
        b = bytearray(self.opcode[bcc_type.lower()][0])
        inst = (b[0] << 8) | (offset & 0xff)
        jmp_offset = struct.pack('<i', inst)
        return jmp_offset

    def fill_thumb2_bcc_inst_by_offset(self, bcc_type, start, offset):
        thumb2_inst = self.opcode[bcc_type.lower()]
        sign = 0
        if offset < 0:
            sign = 1
        #high
        b0 = bytearray(thumb2_inst[0])
        b1 = bytearray(thumb2_inst[1])
        high = ((b0[0] | (sign << 2)) << 8) | ((b1[0] | ((offset >> 11) & 0x3f)))
        jmp_offset1 = struct.pack('<i', high)

        #low
        b2 = bytearray(thumb2_inst[2])
        b3 = bytearray(thumb2_inst[3])
        low = ((b2[0] | ((offset >> 8) & 0x7)) << 8) | ((b3[0] | (offset & 0xff)))
        jmp_offset2 = struct.pack('<i', low)

        return jmp_offset1, jmp_offset2