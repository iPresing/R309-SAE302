import socket
import sys
import random
import threading

#host = "127.0.0.1"
#port = 1234
#message = "Hello World !"
global connected
connected = False

class ChallengeRefused(Exception): # erreur customisée en lien avec le challenge
    def __init__(self, message):
        super().__init__(message)


def main(host="127.0.0.1", port=1234):
    challenge = ",".join([str(random.randint(1,65535) * 2) for i in range(16)]) # un challenge pour reconnaître une connexion autorisée
    try:
        client_socket.connect((host, port))
        client_socket.send(challenge.encode())
        synced = client_socket.recv(1024).decode() # on attend la réponse du serveur pour continuer
        if not(synced == "synced"):
            raise ChallengeRefused("You're not allowed to access to this server...")
    except ChallengeRefused as err:
        print("Erreur :", err)
    else:
        print("You're connected to the server !")
        interactive(host)
        
    return 0 #print(host,port,challenge)

def send(socket, host):
    global connected
    while connected:
        msg = input(f"you@{host} $:")
        socket.send(msg.encode()) if msg else None
        if msg == "bye" or msg == "arret":
            connected = False
            socket.close()
            break
        msg = None
        
    return 0

def receive(socket, host):
    global connected
    while connected:
        reply = socket.recv(1024).decode()
        print(f"\nserver :",reply) if reply else None
        if reply == "bye" or reply == "arret":
            connected = False
            socket.close()
            break
        reply = None
    return 0

def interactive(host):
    global connected
    connected = True
    print("Interactive mode")
    threading.Thread(target=receive, args=(client_socket,host)).start()
    threading.Thread(target=send, args=(client_socket,host)).start()
    
    
    
    """     while connected:
        message = input(f"you@{host} $:")
        print(f"you@{host} $:", message) if message else None
        client_socket.send(message.encode()) if message else None
        reply = client_socket.recv(1024).decode()
        print(f"server@{host} $:",reply) if reply else None
        reply = None
        message = None """
    
    return 0 


if __name__ == "__main__":
    # commun à tous les clients
    client_socket = socket.socket()
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        print("Connecting to host: ", host, "with port: ", port)
        main(host, port)
    elif len(sys.argv) == 2:
        host = sys.argv[1]
        print("Connecting to host: ", host, "with default port")
        main(host)
    else:
        print("Connecting to default host and port (localhost:1234)")
        main()
        
        
        
        

""" def send(target, message):
    target.send(message.encode())


client_socket.connect((host, port))
client_socket.send(message.encode())

reply = client_socket.recv(1024).decode()
print(reply)
client_socket.close()
 """

