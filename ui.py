import eel
import sqlite3
import datetime
from time import time

def main(pu_keys, ui_in, ui_ot, my_key):
    global c, conn, ui_out, pub_keys, my_pub_key, sqlite3
    pub_keys = pu_keys
    ui_out = ui_ot
    my_pub_key = my_key
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    eel.init("ui")
    eel.start("index.html", block=False, size=(1024, 768), position=(0,0))

    while True:
        if not ui_in.empty():
            a, b = ui_in.get()
            if a == "new":
                timestamp, msg, sender, encryption, rec_key = b
                eel.add_msg_start(timestamp, msg, sender, encryption, rec_key)
        eel.sleep(2.0)


@eel.expose
def import_key(new_key, name):
    if new_key not in list(pub_keys.keys()):
        c.execute(f"""CREATE TABLE '{new_key}' (
            timestamp INTEGER,
            message TEXT,
            sender INTEGER,
            encryption INTEGER)
            """)
        init_msg = "Začal si komunikáciu, ešte nemôžeš posielať šifrované správy"
        c.execute(f"INSERT INTO '{new_key}' VALUES (?,?,?,?);", (int(time()), init_msg, 3, 1))
        conn.commit()
        ui_out.put(("import", (new_key, name)))


@eel.expose
def export_key():
    eel.insert_exported_key(my_pub_key)


@eel.expose
def send_msg(msg, receiver_key, encryption):
    global time, datetime
    if len(msg.encode("utf-8").hex()) <= 1000:
        current_time = int(time())
        timestamp = datetime.datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        print("putujem do ui_out")
        ui_out.put(["send", [receiver_key, msg, encryption]])
        #c.execute(f"INSERT INTO '{receiver_key}' VALUES (?,?,?,?);", (current_time, msg, 1, int(encryption)))
        #conn.commit()
        eel.add_msg_start(timestamp, msg, "Me", encryption, receiver_key)


@eel.expose
def request_keys():
    if pub_keys == {}:
        return
    user_keys = []
    for key in pub_keys:
        c.execute(f"SELECT * FROM '{key}' WHERE rowid = (SELECT MAX(rowid) FROM '{key}')")
        query = c.fetchone()
        if not query[2]:
            query[2] == pub_keys[key][0]
        elif query[2] :
            query[2] == "Me"
        else:
            query[2] == "Info"
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
        if not query[2]:
            query[2] = name
        elif query[2]:
            query[2] = "Me"
        else:
            query[2] = "Info"
        eel.add_msg_end(query[0], query[1], query[2], bool(query[3]), rowid)
        rowid -= 1
    eel.update_scroll()
