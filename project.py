
class Project:
    def __init__(self, filename, offset):
        self.filename = filename
        self.base_offset = offset
        self.origin_data = None