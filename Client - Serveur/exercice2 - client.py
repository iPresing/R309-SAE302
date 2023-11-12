import socket
import sys
import random
import threading
import select
from colorama import init, Fore, Back, Style

init(autoreset=True) # pour que les couleurs s'appliquent à tout le terminal

#host = "127.0.0.1"
#port = 1234
#message = "Hello World !"
global connected
connected = False

class ChallengeRefused(Exception): # erreur customisée en lien avec le challenge
    def __init__(self, message):
        super().__init__(message)
        
class ConnectionClosedByServer(Exception):
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
    except ConnectionRefusedError as err:
        print(Fore.RED + " \nLa connexion n'a pas aboutie, vérifiez que le serveur est bien lancé et que l'adresse est correcte")
    else:
        print(Fore.GREEN + "You're connected to the server !")
        interactive(host)
        
    return 0 #print(host,port,challenge)

def send(socket, host):
    global connected
    global msg
    while connected:
        try:
            msg = input(f"you@{host} $:")
            socket.send(msg.encode()) if msg else None
            if msg == "bye" or msg == "arret":
                connected = False
                socket.close()
                break
            msg = None
        except ConnectionAbortedError as err:
            print(Fore.RED + "La connexion a été interrompue par le serveur") \
                if not msg == "bye" \
                    else print(Fore.GREEN + "Vous avez bien été déconnecté du serveur")
            break
        else: 
            pass       
    return 0

def receive(socket, host):
    global connected
    global msg # récupérer le dernier msg envoyé par le client
    while connected:
        try:
            reply = socket.recv(1024).decode()
            print(f"\nserver :",reply) if reply else None
            if reply == "bye" or reply == "arret":
                connected = False
                socket.close()
                raise ConnectionClosedByServer('closed connection')
                break
            reply = None
        except ConnectionClosedByServer as err:
            print(Fore.GREEN + "Vous avez bien été déconnecté du serveur")
            break
        except ConnectionAbortedError as err:
            print(Fore.RED + "La connexion a été interrompue par le serveur") \
                if not msg == "bye" \
                    else print(Fore.GREEN + "Vous avez bien été déconnecté du serveur")
            break
        else: 
            pass
        
    return 0

def interactive(host):
    global connected
    connected = True
    print("Interactive mode")
    #send(client_socket,host) # ne pas le mettre dans un thread pour qu'il puisse gérer activement l'input
    threading.Thread(target=receive, args=(client_socket,host)).start()
    send(client_socket,host) # ne pas le mettre dans un thread pour qu'il puisse gérer activement l'input
    #threading.Thread(target=send, args=(client_socket,host)).start()
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

