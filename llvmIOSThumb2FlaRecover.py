from thumb2FlaRecover import Thumb2FlaRecover


class LLVMIOSThumb2FlaRecover(Thumb2FlaRecover):
    def __init__(self, data, offset):
        Thumb2FlaRecover.__init__(self, data, offset)