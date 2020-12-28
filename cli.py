def cli(com, display, prnt):
    while True:
        if not prnt.empty():
            while not prnt.empty():
                print(prnt.get())
        a = input("zadaj daco(help): ")
        if a == "con":
            b = input("zadaj adresu: ")
            c = input("zadaj port (ak prazdne tak default): ")
            if c == "":
                c = 9999
            c = int(c)
            com.put([a, [b, c]])
        elif a == "send":
            com.put([a, ["", "", ""]])
            while display.empty():
                pass
            key_list = display.get()
            for i in key_list:
                v = "no"
                if key_list[i][1] != "no" or key_list[i][1] != "sent":
                    v = "yes"
                print(f"{key_list[i][0]}: {i} | encryption: {v}")
            while True:
                try:
                    b = input("zadaj cislo mena(0-n, stop-ukoncit tento command): ")
                    if b == "stop":
                        break
                    b = int(b)
                    if 0 <= b < len(key_list):
                        break
                    else:
                        print("zle zadane cislo")
                except:
                    print("mezadal si cislo")
            if type(b) == type(""):
                continue
            c = input("zadaj spravu: ")
            d = ""
            while d != "0" and d != "1" and d != "stop":
                d = input("sifrovat spravu (0-nie, 1-ano, stop-ukoncit tento command): ")
            if d == "stop":
                continue
            com.put([a, [b, c, d]])
        elif a == "import":
            b = input("zadaj kluc: ")
            c = input("zadaj meno: ")
            com.put([a, [b, c]])
        elif a == "export":
            com.put([a, ""])
            while display.empty():
                pass
            print(display.get())
        elif a == "lsimported":
            com.put([a, ""])
            while display.empty():
                pass
            dict = display.get()
            for i in dict:
                v = "no"
                if dict[i][1] != "no" or dict[i][1] != "sent":
                    v = "yes"
                print(f"{dict[i][0]}: {i} | encryption: {v}")
        elif a == "lsnodes":
            com.put([a, ""])
            while display.empty():
                pass
            for i in display.get():
                print(f"{i.address}: {i.authorized}")
        elif a == "start mining":
            com.put([a, ""])
        elif a == "stop mining":
            com.put([a, ""])
        elif a == "highest":
            com.put([a, ""])
        elif a == "nodesdb":
            com.put([a, ""])
        elif a == "help":
            print("""\n            con - manualne sa pripoj na node
            send - posli spravu
            import - importuj publick key
            export - tvoj publick key
            lsimported - list importnutych klucov
            lsnodes - list prave pripojenych nodov
            start mining
            stop mining
            highest - najvyssi block
            end - koniec programu\n""")
        elif a == "end":
            com.put([a, ""])
            break
