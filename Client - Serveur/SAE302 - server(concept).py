import socket
import threading
from colorama import init, Fore, Back, Style
from numpy import random
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# exception permettant de prévenir de l'envoie d'un "bye" général
class LogoutBroadcast(Exception):
    def __init__(self, message):
        super().__init__(message)
        
        
# Configuration du serveur
host = "0.0.0.0"
port = 1234
global connected
global socket_list
connected = True
socket_list = {}
key = os.environ['AES_KEY'].encode() # récupérer depuis les variables d'environnements
iv = os.environ['AES_IV'].encode() #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)

# Liste de pseudos par défaut
default_pseudo =  ["Nosferatu","BlackBird","Pleiades","Hyades","Undertaker","BloodyReina","Wehrwolf","LaughingFox","SnowWitch"\
    ,"Gunslinger","Sagittarius","Cyclops","Melusine","Bluebell","Verethragna","Hualien","Milan","Baldanders","Catoblepas","Banshee"\
    ,"Grimalkin","Bandersnatch","Jabberwock","Dullahan","Kirschblüte","BlackDog","Falke","Fafnir","Helianthus","Walpurgis","Griffin",\
    "Manticore","Artemis","Cato'Nine","MarchHare","Sirius","Leukosia","Gunmetalstorm","LaBete","Dendroaspis","Burnt Tayl","Gladiator",\
    "Argos","Vulture","Estoc","Grimoire","Gungnir","GaeBolg","Excalibur","Durandal","ClaiomhSolais",\
"Caladbolg","Balmung","AmeNoMurakumo"]


# récupérer le pseudo à partir de la valeur "socket"
def username(dictionary, value):
    for key, val in dictionary.items():
        if val == value:
            return key
    # Si la valeur n'est pas trouvée, vous pouvez retourner une valeur par défaut ou générer une exception.
    # Par exemple, vous pouvez lever une exception KeyError :
    # raise KeyError(f"Aucune clé trouvée pour la valeur {value}")
    return None  # Ou retourner None




# Fonction pour envoyer des messages
def send(socket, host):
    global connected
    global socket_list
    hostup = True
    while hostup:
        try:
            msg = input(f"server@{host} $:")
            print("\033[1A\033[2K", end="")  # up + clear line
            print(f"you: {msg}") if msg else None
            if len(socket_list) > 1 and msg == "bye": # dans le cas où il y a plusieurs clients
                raise LogoutBroadcast("Attention vous vous apprêtez à envoyer un message de déconnexion à tous les clients")
            else:
                socket.send(msg.encode()) if (msg and not "bye" in msg) else None
        except ConnectionResetError:
            #hostup = False
            socket.close()
            print("La connexion a été interrompue par le client")
            break
        except OSError:  # quand le socket est fermé
            break
        except LogoutBroadcast as err: # un avertissement (non punitif)
            print(Fore.RED + str(err) + \
                " voici la bonne syntaxe ex: \"bye arnaud\"", \
                end=f"\n{Fore.RESET}")
            pass
        else:
            if "bye" in msg and len(msg) > 3:
                username = msg.split(" ")[1]
                try:
                    target_socket = socket_list[username] # essaie de récupérer le socket avec le username
                except KeyError as err:
                    print(Fore.RED + f"Le pseudo {username} n'existe pas", end=f'\n{Fore.RESET}')
                    pass
                else:
                    username, target_socket = socket_list.popitem()
                    target_socket.send("bye".encode())
                    target_socket.send("recon".encode())
            if msg == "arret":
                hostup = False
                break
            msg = None
    socket.close()

# Fonction pour recevoir des messages
def receive(socket, host):
    global hostup
    global connected
    hostup = True
    while hostup:
        try:
            reply = socket.recv(1024).decode()
        except ConnectionResetError:
            #hostup = False
            print("La connexion a été interrompue par le client")
            socket.close()
            break
        except ConnectionAbortedError:
            #hostup = False
            print("Le serveur a fermé sa connexion")
            socket.close()
            break
        else:
            print("\033[2K", end="\r ")  # carriage return + clear line
            print(f"{username(socket_list,socket)}: {reply}")
            print('\033[1F', f'\nserver@{host} $:', end="") if reply else None
            if reply == "arret":
                hostup = False
                break
            reply = None
    socket.close()

# Fonction pour l'interaction avec le client
def interactive(target, host):
    global connected
    global socket_list
    connected = True
    print("Connected to client")
    threading.Thread(target=receive, args=(target, host)).start() 
    send(target, host) 
    target.close()
    return 0

# Création du socket serveur
server_socket = socket.socket()
server_socket.bind((host, port))
server_socket.listen(5)

# Boucle principale d'attente de connexions
while connected:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    conn, address = server_socket.accept()
    message = conn.recv(1024)
    message_1 = unpad(cipher.decrypt(message), AES.block_size).decode()

    #message_2 = conn.recv(1024).decode()
    client_challenge = message_1.split(";")[0].split(",")
    credentials = message_1.split(";")[1].split(",")
    connect_condition = lambda x: int(x) % 2 == 0
    client_condition = all(connect_condition(elem) for elem in client_challenge)
    if client_condition:
        unique_pseudo = random.choice(default_pseudo, replace=False) \
            if credentials[0] == "default" \
                else credentials[0]  # choisir un pseudo unique si pas de user dans credentials
        
        # ajouter au dictionnaire socket_list une entrée avec clé le pseudonyme et comme valeur le socket
        socket_list[f"{unique_pseudo}"] = conn
        conn.send(f"synced,{unique_pseudo}".encode())
        threading.Thread(target=interactive, args=(conn, host)).start()
        conn.close() if not connected else None
    else:
        conn.send("garbage".encode())
        conn.close()
