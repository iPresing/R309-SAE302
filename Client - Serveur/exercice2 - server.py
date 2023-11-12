import socket
import threading

host = "0.0.0.0"
port = 1234
#reply = "synced"
#message = "Hello World !"
global connected 
connected = True

def send(socket, host):
    global connected
    while connected:
        msg = input(f"server@{host} $:")
        socket.send(msg.encode()) if msg else None
        if msg == "arret":
            connected = False
            #socket.close()
            break
        msg = None
    return 0
        
def receive(socket, host):
    global connected
    while connected:
        try:
            reply = socket.recv(1024).decode()
        except ConnectionResetError:
            print("La connexion a été interrompue par le client")
            break
        else:
            print(f"\nclient :",reply) if reply else None
            if reply == "arret":
                connected = False
                #socket.close()
                break
            reply = None    
    return 0

def interactive(target, host):
    global connected
    connected = True
    print("Connected to client")
    threading.Thread(target=receive, args=(target,host)).start()
    #threading.Thread(target=send, args=(target,host)).start()
    send(target,host) # ne pas le mettre dans un thread pour qu'il puisse gérer activement l'input
    return 0
    """ while connected:
        reply = target.recv(1024).decode()
        print(f"client@{host} $:", reply) if reply else None
        message = input(f"server@{host} $:")
        target.send(message.encode()) if message else None
        #print(f"server@{host} $:",message) if message else None
        reply = None
        message = None """
        

server_socket = socket.socket()
server_socket.bind((host, port))
server_socket.listen(5)


while connected: # remplacer shutdown plutôt
    conn, address = server_socket.accept()
    message = conn.recv(1024).decode()
    client_challenge = message.split(",")
    connect_condition = lambda x: int(x) % 2 == 0
    client_condition = all(connect_condition(elem) for elem in client_challenge)
    if client_condition:
        conn.send("synced".encode())
        #threading.Thread(target=interactive, args=(conn,host)).start()
        interactive(conn, host)
        conn.close()
        #conn.close()
    else:
        conn.send("garbage".encode())
        conn.close()




#print(reply)

#conn.send(reply.encode())



