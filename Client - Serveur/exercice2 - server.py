import socket

host = "0.0.0.0"
port = 1234
#reply = "synced"
#message = "Hello World !"



server_socket = socket.socket()
server_socket.bind((host, port))
server_socket.listen(1)
conn, address = server_socket.accept()
message = conn.recv(1024).decode()

client_challenge = message.split(",")

connect_condition = lambda x: int(x) % 2 == 0
client_condition = all(connect_condition(elem) for elem in client_challenge)

def interactive(target):
    connected = True
    print("Connected to target")
    while connected:
        reply = target.recv(1024).decode()
        print(f"client@{host} $:", reply) if reply else None
        message = input(f"server@{host} $:")
        target.send(message.encode()) if message else None
        #print(f"server@{host} $:",message) if message else None
        reply = None
        message = None

if client_condition:
    conn.send("synced".encode())
    interactive(conn)
    #conn.close()
else:
    conn.send("garbage".encode())
    conn.close()



#print(reply)

#conn.send(reply.encode())



