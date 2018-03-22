
class InstUtil:
    def __init__(self):
        self.opcode = None

    def get_nop_code(self):
        if self.opcode == None:
            return None
        return self.opcode['nop']