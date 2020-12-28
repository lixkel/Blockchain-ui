def start_node(port, nodes, inbound, outbound, ban_list, log):
    import socket
    from time import time
    global socket, time
    from node import node
    global server_socket, sockets_list
    global logging
    logging = log
    host = "0.0.0.0"
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setblocking(0)
    bind_socket(host, port)
    sockets_list = [server_socket]
    main(nodes, inbound, outbound, ban_list)


def main(nodes, inbound, outbound, ban_list):
    import select
    from node import node
    global socket, time
    global server_socket
    global sockets_list
    while True:
        read_sockets, write, exception_sockets = select.select(sockets_list, sockets_list, sockets_list, 0)
        for soc in read_sockets:
            if soc == server_socket:
                new_soc = server_socket.accept()
                if new_soc[1] not in ban_list:
                    new_node = node(new_soc, True, "version", int(time()))
                    sockets_list.append(new_node.socket)
                    nodes[new_node.address] = new_node
            else:
                new_message = receive_message(soc)
                if not new_message:
                    sockets_list.remove(soc)
                    try:#ked je new message false mozu sa stat 2 moznosti ze je error na packete alebo som len dostal close alebo b""
                        del nodes[soc.getpeername()]#v prvom pripade toto fungovat nebude socket vyhodi error
                    except:
                        del_bad_soc(nodes)
                else:
                    if new_message != "error":
                        nodes[soc.getpeername()].lastrecv = int(time())
                    inbound.put([soc, new_message])

        for exception in exception_sockets:
            sockets_list.remove(expection)
            del nodes[exception.getpeername()]

        if not outbound.empty():
            comm, body = outbound.get()
            if comm == "connect":
                addr, port, vers = body
                new_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    new_soc.settimeout(5)
                    new_soc.connect((addr, port))
                    new_soc.settimeout(None)
                    new_node = node((new_soc, new_soc.getpeername()), False, "version", int(time()))
                    sockets_list.append(new_node.socket)
                    nodes[new_node.address] = new_node
                    send_message(new_node.socket, vers, nodes)
                except socket.error as e:
                    inbound.put([(addr, port), "error"])
                    logging.debug(f"Address-related error connecting to server: {e}")
            elif comm == "send":
                soc, message = body
                suc_send = send_message(soc, message, nodes)
                if not suc_send:
                    outbound.put(["close", soc.getpeername()])
            elif comm == "broadcast":
                skip_soc, tx = body
                for soc in sockets_list:
                    if soc == server_socket or soc.getpeername() == skip_soc:
                        continue
                    send_message(soc, tx, nodes)
            elif comm == "close":
                for soc in sockets_list:
                    if soc == server_socket:
                        continue
                    if soc.getpeername() == body:
                        send_message(soc, b"close", nodes)
                        sockets_list.remove(soc)
                        try:
                            del nodes[soc.getpeername()]
                        except:
                            del_bad_soc(nodes)
                        soc.close()
            elif comm == "end":
                for soc in sockets_list:
                    if soc != server_socket:
                        send_message(soc, b"close", nodes)
                    soc.close()
                break


def send_message(soc, message, nodes):
    global socket, time
    try:
        totalsent = 0
        while totalsent < len(message):
            sent = soc.send(message[totalsent:])
            if sent == 0:
                return False
            totalsent = totalsent + sent
        try:
            nodes[soc.getpeername()].lastsend = int(time())
        except:
            del_bad_soc(nodes)
        return True
    except socket.error as e:
        logging.debug(f"Error sending data: {e}")


def bind_socket(host, port):
    global socket
    try:
        global server_socket
        server_socket.bind((host, port))
        server_socket.listen()

    except socket.error as e:
        logging.debug(f"Socket Binding error {e}\nRetrying...")
        bind_socket()


def receive_message(soc):
    global socket
    try:
        chunks = []
        bytes_recv = 0
        while bytes_recv < 16:
            chunk = soc.recv(16 - bytes_recv)
            if chunk == b"":
                return False
            chunks.append(chunk)
            bytes_recv = bytes_recv + len(chunk)
            message_header = b"".join(chunks)
            if message_header == b"close":
                return False
        message_header = message_header.hex()
        payload_lenght = int(message_header[24:], 16)
        chunks = []
        bytes_recv = 0
        while bytes_recv < payload_lenght:
            chunk = soc.recv(min(payload_lenght - bytes_recv, 2048))
            if chunk == b"":
                return False
            chunks.append(chunk)
            bytes_recv = bytes_recv + len(chunk)
        payload = b"".join(chunks)
        return message_header + payload.hex()
    except socket.error as e:
        logging.debug(f"Error receiving data: {e}")
        return False


def del_bad_soc(nodes):
    for i in list(nodes.keys()):
        try:
            nodes[i].socket.getpeername()
        except:
            del nodes[i]
