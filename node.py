class node:
    def __init__(self, output, inbound, exp, timestamp):
        self.socket, self.address = output
        self.authorized = False
        self.inbound = inbound
        self.expecting = exp
        self.best_height = 0
        self.port = self.address[1]
        self.lastrecv = timestamp
        self.lastsend = timestamp
        self.banscore = 0
