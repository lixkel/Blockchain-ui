import eel
import sqlite3
import datetime
from time import time

def main(pu_keys, ui_in, ui_ot):
    global c, conn, ui_out, pub_keys, pub_keys, sqlite3
    pub_keys = pu_keys
    ui_out = ui_ot
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    eel.init("ui")
    eel.start("index.html", block=False, size=(1024, 768), position=(0,0))

    while True:
        if not ui_in.empty():
            pass
        eel.sleep(2.0)


@eel.expose
def import_key(new_key, name):
    if new_key not in nodes.keys():
        c.execute("""CREATE TABLE (?) (
            timestamp INTEGER,
            message TEXT,
            sender INTEGER)
            """, (new_key,))
        conn.commit()
    ui_out.put(("import", (new_key, name)))


@eel.expose
def send_msg(msg, receiver_key, encryption):
    global time, datetime
    if len(msg.encode("utf-8").hex()) <= 1000:
        timestamp = datetime.datetime.utcfromtimestamp(int(time())).strftime('%Y-%m-%d %H:%M:%S')
        eel.add_msg_start(timestamp, msg, "Me")


@eel.expose
def request_keys():
    if pub_keys == {}:
        return
    user_keys = []
    for key in pub_keys:
        print(key)
        c.execute(f"SELECT * FROM '{key}' WHERE rowid = (SELECT MAX(rowid) FROM '{key}')")
        query = c.fetchone()
        if query[2] == 0:
            query[2] == pub_keys[key][0]
        else:
            query[2] == "Me"
        user_keys.append([query[0], query[1], query[2], key])
    user_keys.sort(key=lambda x: x[0])
    for key in user_keys:
        key[0] = datetime.datetime.utcfromtimestamp(key[0]).strftime('%Y-%m-%d %H:%M:%S')
    for key in user_keys:
        eel.add_key(key[0], key[1], key[2], key[3], pub_keys[key[3]][0])


@eel.expose
def request_msg(key, current_rowid):
    name = pub_keys[key][0]
    if not current_rowid:
        c.execute(f"SELECT MAX(rowid) FROM '{key}'")
        rowid = c.fetchone()[0]
    else:
        rowid = current_rowid
    for i in range(min(20, rowid)):
        c.execute(f"SELECT * FROM '{key}' WHERE rowid = (?)", (rowid,))
        query = list(c.fetchone())
        query[0] = datetime.datetime.utcfromtimestamp(query[0]).strftime('%Y-%m-%d %H:%M:%S')
        if query[2] == 0:
            query[2] = name
        else:
            query[2] = "Me"
        rowid -= 1
        print(query)
        eel.add_msg_end(query[0], query[1], query[2])
