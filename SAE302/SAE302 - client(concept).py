import socket
import sys
import random
import threading
from colorama import init, Fore, Back, Style
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import argparse

# configuration client
init(autoreset=True) # pour que les couleurs s'appliquent à tout le terminal
global connected    
connected = False
key = os.environ['AES_KEY'].encode() # récupérer depuis les variables d'environnements
iv = os.environ['AES_IV'].encode() #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)



class ChallengeRefused(Exception): # erreur customisée en lien avec le challenge
    def __init__(self, message):
        super().__init__(message)
        
class ConnectionClosedByServer(Exception):
    def __init__(self, message):
        super().__init__(message)

# Instancier les arguments
def arg_parse():
    parser = argparse.ArgumentParser(description='Client pour le chat')
    parser.add_argument('--host', type=str,
                    help='L\'ip du serveur hôte', default="127.0.0.1")
    parser.add_argument('--port', type=int,
                    help='Le port du serveur hôte', default=1234)
    return parser.parse_args()

def encrypt(payload): # pour automatiser encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))

def decrypt(payload): # pour automatiser decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(payload), AES.block_size).decode()

def main(host, port):
    global username
    cipher = AES.new(key, AES.MODE_CBC, iv)
    user = input("Username: ") or "default"
    password = input("Password: ")
    while not password:
        password = input("Password: ")
    challenge = ",".join([str(random.randint(1,65535) * 2) for i in range(16)]) # un challenge pour reconnaître une connexion autorisée
    payload = (challenge + ";" + user + "," + password).encode()
    try:
        client_socket.connect((host, port))
        client_socket.send(encrypt(payload))
        synced = client_socket.recv(1024).decode() # on attend la réponse du serveur pour continuer
        if not "synced" in synced:
            raise ChallengeRefused("You're not allowed to access to this server...")
    except ChallengeRefused as err:
        print(Fore.RED + str(err))
    except ConnectionRefusedError as err:
        print(Fore.RED + " \nLa connexion n'a pas aboutie, vérifiez que le serveur est bien lancé et que l'adresse est correcte")
    else:
        username = synced.split(',')[1]
        #print(Fore.GREEN + "You're connected to the server !")
        print(Fore.GREEN + f"Welcome {username} !") 
        interactive(host)
        
    return 0 #print(host,port,challenge)

def send(socket, host):
    global connected
    global msg
    while connected:
        try:
            msg = input(f"{username}@{host} $:")
            print("\033[1A\033[2K",end="")  # up + clear line 
            print(f"you: ",msg, end="\n") if msg else None
            #print('\033[1F',f'\n', end="") if msg else None # descebdre le curseur et afficher le prompt
            socket.send(msg.encode()) if msg else None
            if msg == "bye" or msg == "arret":
                connected = False
                socket.close()
                break
            msg = None
        except ConnectionAbortedError as err:
            print(Fore.RED + "\rLa connexion a été interrompue par le serveur") \
                if not msg == "bye" \
                    else print(Fore.GREEN + "\rVous avez bien été déconnecté du serveur")
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
            print("\r\033[2K",end="")  # carriage return + clear line 
            print(f"server: ",reply, end="") if reply else None
            print('\033[1F',f'\n{username}@{host} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
            if reply == "bye" or reply == "arret":
                connected = False
                socket.close()
                raise ConnectionClosedByServer('closed connection')
                break
            reply = None
        except ConnectionClosedByServer as err:
            print(Fore.GREEN + "\rVous avez bien été déconnecté du serveur")
            break
        except ConnectionAbortedError as err:
            print(Fore.RED + "La connexion a été interrompue par le serveur") \
                if not msg == "bye" \
                    else print(Fore.GREEN + "\rVous avez bien été déconnecté du serveur")
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
    
    return 0 


if __name__ == "__main__":
    args = arg_parse()
    # commun à tous les clients
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if len(sys.argv) > 1: # si le client donne un argument ou plus 
        print("Connecting to host: ", args.host, "with port: ", args.port)
    else:
        print("Connecting to default host and port (localhost:1234)")
    main(args.host, args.port) # lancer le client

    
        
        


