class Blockchain:
    def __init__(self, version, send_message, sync1, ui_in, log):
        import sqlite3
        from time import time
        from os import urandom
        from hashlib import sha256
        from alter_chain import alter_chain
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        global time, urandom, alter_chain, sha256, serialization, Cipher, modes, ChaCha20, Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey, X25519PublicKey, HKDF, SHA256, backend
        global logging
        global sync
        sync = sync1
        logging = log
        self.version = version
        self.ui_in = ui_in
        self.conn = sqlite3.connect("blockchain.db")
        self.c = self.conn.cursor()
        self.conn_m = sqlite3.connect("messages.db")
        self.c_m = self.conn_m.cursor()
        self.send_message = send_message
        self.mempool = []
        self.valid_tx = []
        self.pub_keys = {}
        self.orphans = {}
        self.alter_chains = []#[parent block rowid, chainwork, timestamp, [[hash, block],]]
        self.c.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='blockchain'")
        if self.c.fetchone()[0] != 1:
            self.c.execute("""CREATE TABLE blockchain (
                hash TEXT,
                block TEXT,
                chainwork INTEGER)
                """)
            genesis = "0000000100000000000000000000000000000000000000000000000000000000000000009ee453f4661baadf27aa2ad55b9f0916c5af9146b2bc5e30531cf9ead14faab400000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6004cc1000036ac401020018536ec3a1c48f20746f20627564652066756e676f7661c5a56004cc10bb03a30a81630d8447b38c7ebcdd0fbde3c04cb454fb4cad21ce98aaa375a82735f7319b55185034598c724e59999cd971eeec93f48a9d1b3470501e2d8821dd9014b0b4e7976b641e322e6ec8d4b6c8e2195a4baf8a43ca5d28bb2159379d030e531f2da8e55edb9597e3e959995cdc9b7bc11b6f849e479d9b8536f52d880f"
            gen_hash = self.hash(genesis[:216])
            gen_chainwork = int(2**256/int(genesis[136:200], 16))
            self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (gen_hash, genesis, gen_chainwork))
            self.conn.commit()
        try:
            keyFile = open("keyFile", "r")
            read = keyFile.read().split("\n")
            ed = bytes.fromhex(read[0])
            x = bytes.fromhex(read[1])
            self.private_key = Ed25519PrivateKey.from_private_bytes(ed)
            self.dh_private_key = X25519PrivateKey.from_private_bytes(x)
        except:
            keyFile = open("keyFile", "w")
            self.private_key = Ed25519PrivateKey.generate()
            private_bytes = self.private_key.private_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption()
                                )

            self.dh_private_key = X25519PrivateKey.generate()
            dh_private_bytes = self.dh_private_key.private_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption()
                                )
            keyFile.write(private_bytes.hex() + "\n" + dh_private_bytes.hex())
        keyFile.close()
        self.public_key = self.private_key.public_key()
        self.public_key_hex = self.public_key.public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw
                                )
        self.public_key_hex = self.public_key_hex.hex()

        self.dh_public_key = self.dh_private_key.public_key()
        self.dh_public_key_hex = self.dh_public_key.public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw
                                )
        self.dh_public_key_hex = self.dh_public_key_hex.hex()

        try:
            pubKeyFile = open("pubKeyFile", "r")
            all_keys = pubKeyFile.read().split("\n")[:-1]
            all_keys = all_keys
            for i in all_keys:
                pair = i.split()
                self.pub_keys[pair[0]] = [pair[1], pair[2]]
        except FileNotFoundError:
            pass
        self.c.execute("SELECT rowid, * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        entry = self.c.fetchone()
        self.height = entry[0]
        self.target = entry[2][136:200]
        if self.height % 10 == 0:
            logging.debug("start calc_height")
            self.calc_target()
        self.chainwork = entry[3]
        logging.debug(f"height: {self.height}, target: {self.target}, chainwork: {self.chainwork}")


    def verify_block(self, block):
        block_target = block[136:200]
        block_target = int(block_target, 16)
        header_hash = self.hash(block[:216])
        if not int(header_hash, 16) <= block_target:
            logging.debug("block invalid target")
            return False
        num_tx = int(block[216:218], 16)
        if num_tx > 255:
            logging.debug("block invalid prilis vela tx")
            return False
        index = 218
        tx_remaining = 270
        tx_hashes = []
        for i in range(num_tx):
            tx_type = block[index:index+2]
            if tx_type == "00":
                message_size = 64-4
            elif tx_type == "01":
                message_size = int(block[index+34:index+38], 16) * 2
                message_size += 32
            else:
                message_size = int(block[index+2:index+6], 16) * 2
            tx_size = index + message_size + tx_remaining
            tx = block[index:tx_size]
            if not self.verify_tx(tx, timestamp=block[200:208]):
                logging.debug("block invalid tx")
                return False
            tx_hashes.append(self.hash(tx))
            index = tx_size
        merkle_root = self.merkle_tree(tx_hashes)
        if merkle_root != block[72:136]:
            logging.debug(block[72:136])
            logging.debug("block merkle root invalid")
            return False
        logging.debug("block True")
        return True


    def verify_tx(self, tx, timestamp=None):
        global Ed25519PublicKey
        logging.debug(tx)
        if tx in self.mempool:
            logging.debug("tx True already have")
            return "already"
        elif tx in self.valid_tx:
            logging.debug("tx already in valid_tx")
            if timestamp:#ak vola turo funkciu verify_block
                return False#aby v blockchaine nemohli byt dve tie iste tx
            return "already"
        tx_type = tx[:2]
        if not tx_type in ["00", "01", "02"]:
            logging.debug(f"invalid tx type: {tx_type}")
            return False
        if tx_type == "00":
            msg_size = 64-4
        elif tx_type == "01":
            msg_size = int(tx[34:38], 16) * 2
            msg_size += 32
        else:
            msg_size = int(tx[2:6], 16) * 2
        print(f"msg_size: {msg_size}")
        if msg_size > 2000:
            logging.debug("msg size je moc velka")
            return False
        sig = bytes.fromhex(tx[-128:])
        sender_pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx[-192:-128]))
        try:
            sender_pub_key.verify(sig, bytes.fromhex(tx[:-128]))
        except:
            logging.debug("tx sig False")
            return False
        tx_timestamp = int(tx[-264:-256], 16)
        if timestamp:
            timestamp = int(timestamp, 16)
            if not -1800 <= timestamp - tx_timestamp <= 1800:
                logging.debug("tx timestamp is old in block")
                return False
            #ked bude temp fork a dojdu dva bloky s tymi istymi tx tak ich budem ma t dva krat v db
        elif not -1800 <= int(time()) - tx_timestamp <= 1800:
            logging.debug("tx timestamp is old")
            return False
        logging.debug("tx True")
        return True


    def block_content(self, block):
        num_tx = int(block[216:218], 16)
        index = 218
        tx_remaining = 270
        for i in range(num_tx):
            tx_type = block[index:index+2]
            if tx_type == "00":
                message_size = 64-4
            elif tx_type == "01":
                message_size = int(block[index+34:index+38], 16) * 2
                message_size += 32
            else:
                message_size = int(block[index+2:index+6], 16) * 2
            tx_size = index + message_size + tx_remaining
            tx = block[index:tx_size]
            if tx in self.mempool:
                self.mempool.remove(tx)
                self.valid_tx.append(tx)
            elif tx in self.valid_tx:#pri temp forku by sa toto dalo obist ale to budem riesit asi pri ui verzii
                pass
            else:
                self.tx_content(tx)
                self.valid_tx.append(tx)
            index = tx_size


    def tx_content(self, tx):
        sender = False
        if tx[-192:-128] == self.public_key_hex:
            sender = True
        if tx[-256:-192] == self.public_key_hex or sender:
            tx_type = tx[:2]
            logging.debug(f"{tx_type}")
            if sender:
                peer_pub_key = tx[-256:-192]
            else:
                peer_pub_key = tx[-192:-128]
            timestamp = int(tx[-264:-256], 16)
            try:
                user = self.pub_keys[peer_pub_key]
            except KeyError:
                self.save_key(peer_pub_key)
                user = self.pub_keys[peer_pub_key]
                self.c_m.execute(f"""CREATE TABLE '{peer_pub_key}' (
                    timestamp INTEGER,
                    message TEXT,
                    sender INTEGER,
                    encryption INTEGER)
                    """)
                init_msg = "Komunikácia bola zahájená druhou stranou, ešte nemôžeš posielať šifrované správy"
                self.c_m.execute(f"INSERT INTO '{peer_pub_key}' VALUES (?,?,?,?);", (int(time()), init_msg, 3, 1))
                self.conn_m.commit()
            logging.debug(f"user: {user}")
            if tx_type == "00":
                if sender:
                    if user[1] == "no":
                        user[1] = "sent"
                    return
                logging.debug("som v 00")
                dh_peer_key = X25519PublicKey.from_public_bytes(bytes.fromhex(tx[2:66]))
                shared_key = self.dh_private_key.exchange(dh_peer_key)
                derived_key = HKDF(
                                algorithm=SHA256(),
                                length=32,
                                salt=None,
                                info=b'blockchain',
                                backend=backend,
                                ).derive(shared_key)
                if user[1] == "no":#mozno by som nemal prijimat tx pocas syncovania
                    self.send_message("send", cargo=["", peer_pub_key, "00"])
                self.pub_keys[peer_pub_key][1] = derived_key.hex()
                logging.debug("posuvam do edit key files")
                self.edit_key_file(peer_pub_key, derived_key.hex(), 2)#musim kukat aj tx od seba ktore nemam
                exchange_msg = "Výmena kľúčov prebehla úspešne odteraz môžeš správy posielať šifrované"
                self.c_m.execute(f"INSERT INTO '{peer_pub_key}' VALUES (?,?,?,?);", (timestamp, exchange_msg, 3, 1))
                self.conn_m.commit()
                self.ui_in.put(["new", [timestamp, exchange_msg, "Info", 1, peer_pub_key]])
                return
            elif tx_type == "01":
                nonce = bytes.fromhex(tx[2:34])
                msg_size = int(tx[34:38], 16) * 2
                msg = bytes.fromhex(tx[38:msg_size+38])
                if user[1] == "no" or user[1] == "sent":
                    if user[0] == "__unknown" and user[1] == "no" and not sender:
                        self.del_pub_key(peer_pub_key)
                        del self.pub_keys[peer_pub_key]
                    print("sifrovana sprava ale neprebehla vymena klucov")
                    return False
                encryption_key = bytes.fromhex(user[1])
                algorithm = ChaCha20(encryption_key, nonce)
                cipher = Cipher(algorithm, mode=None, backend=backend)
                decryptor = cipher.decryptor()
                msg = decryptor.update(msg)
                msg = msg.decode("utf-8")
                print(f"{user[0]}: {msg}")
            elif tx_type == "02":
                msg_size = int(tx[2:6], 16) * 2
                msg = bytes.fromhex(tx[6:msg_size+6]).decode("utf-8")
                print(f"{user[0]}: {msg}")
            msg_sender = 0
            name = user[0]
            if sender:
                msg_sender = 1
                name = "Me"
            self.c_m.execute(f"INSERT INTO '{peer_pub_key}' VALUES (?,?,?,?);", (timestamp, msg, msg_sender, int(not int(tx_type)-1)))
            self.conn_m.commit()
            self.ui_in.put(["new", [timestamp, msg, user[0], not int(tx_type)-1, peer_pub_key]])
#tento krkolomny zapis s int meni tx_type "01"=1 a "02"=0 na bit encryption pritom vyuziva ze 0 a 1 sa daju brat ako boolen hodnoty


    def hash(self, tx):
        global sha256
        return sha256(bytes.fromhex(tx)).hexdigest()


    def fill(self, entity, fill):
        lenght = len(entity)
        if lenght < fill:
            miss = fill - lenght
            entity = miss*"0" + entity
        return entity


    def merkle_tree(self, hashes):
        while len(hashes) > 1:
            hashes1 = []
            for i in range(0, len(hashes), 2):
                try:
                    to_hash = hashes[i] + hashes[i+1]
                except IndexError:
                    to_hash = hashes[i] + hashes[i]
                hashes1.append(self.hash(to_hash))
            hashes = hashes1
        if len(hashes) == 0:
            return "0" * 64
        return hashes[0]

    def save_key(self, new_key, nickname="__unknown"):
        enc_key = "no"
        if nickname != "__unknown":
            enc_key = "sent"
        file = open("pubKeyFile", "a")
        file.write(f"{new_key} {nickname} {enc_key}\n")
        self.pub_keys[new_key] = [nickname, enc_key]
        file.close()


    def edit_key_file(self, pub_key, new_value, index):
        file = open("pubKeyFile", "r")
        all_keys = file.read().split("\n")[:-1]
        file.close()
        file = open("pubKeyFile", "w")
        for i in all_keys:
            pair = i.split()
            if pair[0] == pub_key:
                pair[index] = new_value
                file.write(f"{pair[0]} {pair[1]} {pair[2]}\n")
            else:
                file.write(i + "\n")


    def del_pub_key(self, pub_key):
        file = open("pubKeyFile", "r")
        all_keys = file.read().split("\n")[:-1]
        file.close()
        file = open("pubKeyFile", "w")
        for i in all_keys:
            pair = i.split()
            if pair[0] == pub_key:
                continue
            file.write(i + "\n")


    def create_tx(self, msg_type, msg, rec_key):
        global time, urandom
        if msg_type == "00":
            tx = "00" + self.dh_public_key_hex + hex(int(time()))[2:] + rec_key + self.public_key_hex
            tx = bytes.fromhex(tx)
        else:
            print(f"msg: {msg}")
            raw_msg = msg
            msg = msg.encode("utf-8")
            nonce = ""
            if msg_type == "01":
                logging.debug(f"rec_key: {rec_key}")
                for i in self.pub_keys:
                    logging.debug(f"{i}: {self.pub_keys[i]}")
                    if rec_key == i:
                        key = self.pub_keys[i][1]
                        if key == "no" or  key == "sent":
                            ui_in.put(["warning", "S použivateľom ešte neprebehla výmena kľúčov"])
                            return
                        key = bytes.fromhex(key)
                        break
                nonce = urandom(16)
                algorithm = ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None, backend=backend)
                encryptor = cipher.encryptor()
                msg = encryptor.update(msg)
                nonce = nonce.hex()
            msg = msg.hex()
            print(f"msg hex: {msg}")
            if len(msg) <= 2000:
                msg_size = self.fill(hex(len(bytes.fromhex(msg)))[2:], 4)
                current_time = int(time())
                timestamp = hex(current_time)[2:]
                print(f"nonce: {nonce}")
                tx = msg_type + nonce + msg_size + msg + timestamp + rec_key + self.public_key_hex
                tx = bytes.fromhex(tx)
                self.c_m.execute(f"INSERT INTO '{rec_key}' VALUES (?,?,?,?);", (current_time, raw_msg, 1, int(not int(msg_type)-1)))
                self.conn_m.commit()
            else:#tu treba dat aj
                ui_in.put(["warning", "Správa je príliš dlhá"])
        signature = self.private_key.sign(tx)
        tx = tx + signature
        #na toto verify sa treba pozret ked dorobim verify_tx
        if self.verify_tx(tx.hex()) == True:
            return tx
        else:
            logging.debug("vytvorena tx je zla")
        return False


    def build_block(self):
        global time
        if len(self.mempool) >= 255:
            txs_num = "ff"
        else:
            txs_num = hex(len(self.mempool))[2:]
        if len(txs_num) % 2 == 1:
            txs_num = "0" + txs_num
        txs = ""
        hashes = []
        for i in self.mempool:
              txs += i
              hashes.append(self.hash(i))
              if len(hashes) == 255:
                  break
        txs = txs_num + txs
        merkle_root = self.merkle_tree(hashes)
        timestamp = hex(int(time()))[2:]
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        previous_header = self.c.fetchone()[0]
        block_header = self.version + previous_header + merkle_root + self.target + timestamp
        return block_header, txs


    def append(self, new_block, sync):
        new_block_hash = self.hash(new_block[:216])
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
        previous_block = self.c.fetchone()[0]
        if new_block[8:72] != previous_block:
            self.c.execute("SELECT * FROM blockchain WHERE hash = (?);", (new_block_hash,))
            in_blockchain = self.c.fetchone()
            try:
                in_orphans = self.orphans[new_block_hash]
            except KeyError:
                in_orphans = False
            in_alter = False
            for chain in self.alter_chains:
                for i in chain.chain:
                    if i[0] == new_block_hash:
                        in_alter = True
                        break
                if in_alter:
                    break
            if not in_blockchain and not in_orphans and not in_alter:
                self.c.execute("SELECT rowid, * FROM blockchain WHERE hash = (?);", (new_block[8:72],))
                alter = self.c.fetchone()
                if alter:
                    rowid = alter[0]
                    new_chainwork = alter[3] + int(2**256/int(new_block[136:200], 16))
                    self.alter_chains.append(alter_chain(rowid, new_chainwork, int(time()), hash=new_block_hash, block=new_block))
                    return "appended"
                for chain in self.alter_chains:
                    if chain.chain[-1][0] == new_block[8:72]:
                        chain.chainwork += int(2**256/int(new_block[136:200], 16))
                        chain.chain.append([new_block_hash, new_block, chain.chainwork])
                        if chain.chainwork > self.chainwork:
                            rowid = chain.parent + 1
                            alter_row = 0
                            alter_size = len(chain.chain)
                            self.alter_chains.append(alter_chain(chain.parent, 0, int(time())))
                            self.c.execute("SELECT MAX(rowid) FROM blockchain;")
                            max_rowid = self.c.fetchone()[0]
                            while rowid >= max_rowid and alter_row >= alter_size:
                                self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                                set = self.c.fetchone()
                                self.alter_chains[-1].chain.append([set[0], set[1], set[2]])
                                self.alter_chains[-1].chainwork = set[2]
                                append_block = chain.chain[alter_row]
                                self.c.execute("UPDATE blockchain SET hash = (?) block = (?) chainwork = (?) WHERE rowid = (?);", (append_block[0], append_block[1], append_block[2], max_rowid))
                                self.block_content(append_block[1])
                                rowid += 1
                                alter_row += 1
                            while rowid <= max_rowid:
                                self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (rowid,))
                                set = self.c.fetchone()
                                self.alter_chains[-1].chain.append([set[0], set[1], set[2]])
                                self.alter_chains[-1].chainwork = set[2]
                                self.c.execute("DELETE FROM blockchain WHERE rowid=(?)", (rowid,))
                                rowid += 1
                            while alter_row < alter_size:
                                append_block = chain.chain[alter_row]
                                self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (append_block[0], append_block[1], append_block[2]))
                                self.block_content(append_block[1])
                                alter_row += 1
                            self.chainwork = chain.chainwork
                            logging.debug(f"new highest block hash: {chain.chain[-1][0]}")
                            self.alter_chains.remove(chain)
                            self.conn.commit()
                            self.c.execute("SELECT rowid, block FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
                            query = self.c.fetchone()
                            self.height = query[0]
                            self.target = query[1][136:200]
                            if self.height % 10 == 0:
                                logging.debug("append calc_height")
                                self.calc_target()
                            return True
                        return "appended"
                try:
                    a = self.orphans[new_block[8:72]]
                    return "alrdgot"
                except KeyError:
                    pass
                self.orphans[new_block[8:72]] = new_block
                return "orphan"
            else:
                return "alrdgot"
        block_target = new_block[136:200]
        if block_target != self.target:
            logging.debug("append bad block target")
            return False
        if sync and -360 <= int(time()) - int(new_block[208:216], 16) <= 360:
            logging.debug("append bad block timestamp")
            return False
        self.chainwork += int(2**256/int(block_target, 16))
        self.c.execute("INSERT INTO blockchain VALUES (?,?,?);", (new_block_hash, new_block, self.chainwork))
        self.conn.commit()
        self.block_content(new_block)
        self.height += 1
        if self.height % 10 == 0:
            logging.debug("append calc_height")
            self.calc_target()
        return True


    def calc_target(self):
        calc_height = self.height
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (calc_height,))
        heighest = int(self.c.fetchone()[1][200:208], 16)
        self.c.execute("SELECT * FROM blockchain WHERE rowid = (?);", (calc_height - 9,))
        lowest = int(self.c.fetchone()[1][200:208], 16)
        difference = heighest - lowest
        change = float(difference) / 600.0
        if change > 4.0:
            change = 4.0
        elif change < 0.25:
            change = 0.25
        new_target = hex(int(float(int(self.target, 16)) * change))[2:]
        if len(new_target) < 64:
            dif = 64 - len(new_target)
            new_target = ("0" * dif) + new_target
        elif len(new_target) > 64:
            new_target = "f" * 64
        self.target = new_target
        logging.debug(f"difference: {difference}")
        logging.debug(f"difficulty change: {change}")
        logging.debug(f"new target: {self.target}")


    def check_orphans(self, param):#berie ako parameter hash blocku ku ktoremu pozrie ci v orphans nema child a potom zavola append a znovu check_orphans
        if param == "main":
            self.c.execute("SELECT hash FROM blockchain WHERE rowid = (SELECT MAX(rowid) FROM blockchain);")
            top_hash = self.c.fetchone()[0]
        else:
            top_hash = param
        new = []
        try:
            orphan = self.orphans[top_hash]
            if self.append(orphan):
                del self.orphans[top_hash]
                new.append(self.hash(orphan[:216]))
                for i in self.check_orphans(self.hash(orphan[:216])):
                    new.append(orphan)
                return new
        except KeyError:
            pass
        return []
