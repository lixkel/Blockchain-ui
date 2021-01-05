import socket
import select
import sqlite3
import hashlib
import logging
import threading
import traceback
from time import time
from random import randint
from multiprocessing import Queue, Process

import ui
import p2p
from node import node
from proof_of_work import mine
from blockchain import Blockchain

version = "00000001"
stime = int(time())
nodes = {}
mining = None
expec_blocks = 0
opt_nodes = 5
num_time = 0
my_addr = ""
prev_time = int(time())
port = 55555
default_port = 55555
con_sent = False
hardcoded_nodes = (("146.59.15.193", 55555),)
inbound = Queue()
outbound = Queue()
to_mine = Queue()
mined = Queue()
ui_in = Queue()
ui_out = Queue()
ban_list = []
sync = [True, 0, None]#[synced, time of sending, nodes address]
conn = sqlite3.connect("nodes.db")
c = conn.cursor()
logging.basicConfig(filename='blockchain.log', level=logging.DEBUG, format='%(threadName)s: %(asctime)s %(message)s', filemode="w")
