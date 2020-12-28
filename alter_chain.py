class alter_chain:
    def __init__(self, parent, chainwork, timestamp, hash=None, block=None):
        self.parent = parent
        self.timestamp = timestamp
        self.chainwork = chainwork
        if hash == None:
            self.chain = []
        else:
            self.chain = [[hash, block, chainwork]]
