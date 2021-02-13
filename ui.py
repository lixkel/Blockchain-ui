import eel
import sqlite3
import datetime
from time import time

def main(pu_keys, ui_in, ui_ot, my_key, nodes, sync):
    global c, conn, ui_out, pub_keys, my_pub_key, mine, mining_log, sqlite3, connecting, syncing, con_alert, sync_alert
    pub_keys = pu_keys
    ui_out = ui_ot
    my_pub_key = my_key
    mine = False
    connecting = False
    syncing = False
    mining_log = ""
    con_alert = "Prebieha pripájanie k sieti"
    sync_alert = "Synchronizujem blockchain zo sieťou"
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()
    eel.init("ui")
    eel.start("index.html", block=False, size=(650, 750), position=(0,0))

    while True:
        if not ui_in.empty():
            a, b = ui_in.get()
            if a == "new":
                timestamp, msg, sender, encryption, rec_key = b
                timestamp = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                eel.add_msg_start(timestamp, msg, sender, encryption, rec_key)
            elif a == "mined":
                timestamp = datetime.datetime.utcfromtimestamp(b).strftime('%Y-%m-%d %H:%M:%S')
                entry = f"{timestamp} You mined new block\n"
                mining_log += entry
                eel.insert_mining_log(entry)
            elif a == "warning":
                eel.warning(b)
            elif a == "end":
                break
        if nodes == {} and not connecting:
            connecting = True
            eel.new_alert(con_alert)
        if nodes != {} and connecting:
            connecting = False
            eel.rm_alert()
        if not sync[0] and not syncing:
            syncing = True
            eel.new_alert(sync_alert)
        if sync[0] and syncing:
            syncing = False
            eel.rm_alert()
        eel.sleep(2)


def close_callback(route, websockets):
    print(f"route {route}")
    print(f"websock {websockets}")
    if not websockets:
        ui_out.put(["end", ""])


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
        eel.add_msg_start(timestamp, msg, "Me", encryption, receiver_key)
    else:
        eel.warning("Správa je príliš dlhá")


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
        elif query[2] == 3:
            query[2] = "Info"
        else:
            query[2] = "Me"
        eel.add_msg_end(query[0], query[1], query[2], bool(query[3]), rowid)
        rowid -= 1
    if not current_rowid:
        eel.update_scroll()


@eel.expose
def mining():
    global mine
    if mine:
        ui_out.put(["stop mining", None])
        eel.edit_mining("START MINING")
        mining_log = ""
    else:
        ui_out.put(["start mining", None])
        eel.edit_mining("STOP MINING")
    mine = not mine


@eel.expose
def get_mining_log():
    eel.insert_mining_log(mining_log)


@eel.expose
def get_name(key):
    eel.insert_name(pub_keys[key][0])


@eel.expose
def edit(key, new_name):
    pub_keys[key][0] = new_name
    ui_out.put(["edit", [key, new_name]])


@eel.expose
def check_alert():
    eel.rm_all_alerts()
    if connecting:
        eel.new_alert(con_alert)
    elif syncing:
        eel.new_alert(sync_alert)
