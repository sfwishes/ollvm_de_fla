from confusion import Confusion


class BaseFlaFunc(Confusion):
    def __init__(self):
        Confusion.__init__(self)
        self.symbolicExec = None
        self.flaRecover = None

    #must be override
    def load(self, param):
        return

    #must be override
    def type(self):
        return ""
