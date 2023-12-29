"""
Cet extrait de code est un programme client qui se connecte à un serveur à l'aide d'une connexion socket. Il permet à l'utilisateur d'interagir avec le serveur en envoyant et en recevant des messages. Le programme utilise l'algorithme de chiffrement AES pour crypter et décrypter les messages. Il inclut également des fonctionnalités pour gérer les annonces du serveur et rechercher des serveurs sur le réseau local.

L'utilisation de code ANSI permet de correctement positionner le terminal afin d'éviter de rencontrer des artéfacts visuels,
on ne peut malheureusement gérer tous ces artifacts.


Exemple d'utilisation :
python client.py --host 127.0.0.1 --port 1234

Entrées :
- host (chaîne de caractères) : L'adresse IP du serveur à connecter. La valeur par défaut est "127.0.0.1".
- port (entier) : Le numéro de port du serveur à connecter. La valeur par défaut est 1234.
- search (booléen) : Drapeau pour activer le mode de recherche de serveur. La valeur par défaut est False.

Déroulement :
1. Analyser les arguments de la ligne de commande pour obtenir l'adresse du serveur, le port et le drapeau de recherche.
2. Créer un objet socket pour le client.
3. Si le mode de recherche est activé, vérifier si le client s'exécute sur une machine virtuelle. Si ce n'est pas le cas, rechercher des serveurs sur le réseau local en utilisant des paquets UDP.
4. Si un serveur est trouvé, se connecter à celui-ci en utilisant l'adresse et le port.
5. Demander à l'utilisateur un nom d'utilisateur et un mot de passe.
6. Générer une chaîne de défi et l'envoyer au serveur avec le nom d'utilisateur et le mot de passe, cryptés à l'aide de AES.
7. Recevoir la réponse du serveur et vérifier si le défi a été accepté.
8. Si le défi est accepté, afficher un message de bienvenue et entrer en mode interactif.
9. En mode interactif, démarrer deux threads : un pour envoyer des messages et un pour recevoir des messages.
10. Dans le thread d'envoi, demander à l'utilisateur un message et l'envoyer au serveur.
11. Si le message est "/query", envoyer une demande de requête au serveur.
12. Si le message est "/accept" ou "/refuse", envoyer une demande d'acceptation ou de refus d'une requête.
13. Si le message est "/unsubscribe", se désabonner de la salle actuelle.
14. Si le message est "bye" ou "arret", fermer la connexion et quitter le programme.
15. Dans le thread de réception, recevoir des messages du serveur et les afficher.
16. Si un message est reçu avec le préfixe "cmd:", afficher la sortie de la commande.
17. Si un message est reçu avec le préfixe "users:", afficher la liste des utilisateurs.
18. Si un message est reçu avec le préfixe "jn:", afficher la réponse à la jointure.
19. Si un message est reçu avec le préfixe "query:", afficher la réponse à la requête.
20. Si un message est reçu avec le préfixe "us:", afficher la réponse au désabonnement.
21. Si un message est reçu avec le préfixe "fwd:", afficher un message transféré.
22. Si un message est reçu avec le préfixe "old:", restaurer les anciens messages.
23. Si un message est reçu avec le préfixe "bye" ou "arret", fermer la connexion et quitter le programme.

Sorties :
- Le programme affiche divers messages et invites à l'utilisateur.
- Le programme envoie et reçoit des messages vers et depuis le serveur.
"""
import socket
import ssl
import sys
import random
import threading
from colorama import init, Fore, Back, Style
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from subprocess import getoutput as getResults
import os
import argparse
import psutil
from scapy.all import *
import dotenv

# configuration client
init(autoreset=True) # pour que les couleurs s'appliquent à tout le terminal
global connected    
connected = False
#key = os.environ['AES_KEY'].encode() # récupérer depuis les variables d'environnements
#iv = os.environ['AES_IV'].encode() #récupérer depuis les variables d'environnements
#cipher = AES.new(key, AES.MODE_CBC, iv)
dotenv.load_dotenv()
key = os.getenv('AES_KEY').encode() # récupérer depuis les variables d'environnements
iv = os.getenv('AES_IV').encode() #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)


class ChallengeRefused(Exception): # erreur customisée en lien avec le challenge
    def __init__(self, message):
        super().__init__(message)
        
class ConnectionClosedByServer(Exception):
    def __init__(self, message):
        super().__init__(message)

class KickedFromRoom(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class BannedFromServer(Exception):
    def __init__(self, message):
        super().__init__(message)
     
         
        
def cls():
    os.system('cls' if os.name=='nt' else 'clear')

# Instancier les arguments
def arg_parse():
    """
    Fonction permettant de récupérer les arguments de la ligne de commande.
    Mais aussi d'ajouter des explicatifs sur les arguments.
    
    Args:
        None
        
    Returns:
        args (obj): Les arguments de la ligne de commande.
    """
    parser = argparse.ArgumentParser(description='Client pour le chat')
    parser.add_argument('--host', type=str,
                    help='L\'ip du serveur hôte', default="127.0.0.1")
    parser.add_argument('--port', type=int,
                    help='Le port du serveur hôte', default=1234)
    parser.add_argument('--search', action='store_true',
                    help='Activer la recherche (flag)', default=False)
    return parser.parse_args()

def encrypt(payload): # pour automatiser encryption
    """
    Encrypter un payload donné en utilisant l'algorithme de chiffrement AES.
    
    Args:
        payload (bytes): Le payload à chiffrer.

    Returns:
        bytes: Le payload chiffré.
    """   
    
    cipher = AES.new(key, AES.MODE_CBC, iv) # nouveau cipher pour chaque message
    return cipher.encrypt(pad(payload, AES.block_size))

def decrypt(payload): # pour automatiser decryption
    """
    Decrypter un payload donné en utilisant l'algorithme de chiffrement AES.
    
    Args:
        payload (bytes): Le payload à déchiffrer.
    
    Returns:
        str: Le payload déchiffré.
    
    """
    cipher = AES.new(key, AES.MODE_CBC, iv) # nouveau cipher pour chaque message
    return unpad(cipher.decrypt(payload), AES.block_size).decode()

def main(host, port):
    """
    La fonction main est le point d'entrée du programme client. Elle est responsable de la connexion au serveur, de la gestion du processus de défi, et du démarrage du mode interactif pour l'envoi et la réception de messages.

    Args:
        host (str) : L'adresse IP du serveur auquel se connecter.
        port (int) : Le numéro de port du serveur auquel se connecter.

    Returns:
        None

    Raises :
        ChallengeRefused : Si le serveur refuse le défi.
        ConnectionClosedByServer : Si le serveur ferme la connexion de manière inattendue.
    """
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
        if "banni" in synced:
            raise BannedFromServer(synced)
        elif not "synced" in synced:
            raise ChallengeRefused("You're not allowed to access to this server...")
    except BannedFromServer as e:
        print(Fore.RED + str(e))
    except ChallengeRefused as err:
        print(Fore.RED + str(err))
    except ConnectionRefusedError as err:
        print(Fore.RED + " \nLa connexion n'a pas aboutie, vérifiez que le serveur est bien lancé et que l'adresse est correcte")
    else:
        global room
        username = synced.split(',')[1]
        room = synced.split(',')[2].lstrip()
        #print(Fore.GREEN + "You're connected to the server !")
        cls()
        print(Fore.GREEN + f"Welcome {username} !") 
        interactive(host)
        
    return 0 #print(host,port,challenge)


def send(socket, host):
    """
    Envoie un message du client au serveur
    
    
    Args:
       socket (socket): Le socket du client.
        host (str): L'adresse IP du serveur.
        
    Returns:
        None
        
    Raises:
        ConnectionAbortedError : Si la connexion est interrompue par le serveur.
    """
    
    global room
    global connected
    global msg
    while connected:
        try:
            msg = input(f"{username}@{room} $:")
            print("\033[1A\033[2K",end="")  # up + clear line 
            print(f"you: ",msg, end="\n") if msg else None
            #print('\033[1F',f'\n', end="") if msg else None # descebdre le curseur et afficher le prompt
            socket.send(msg.encode()) if msg else None
            if msg == "bye" or msg == "arret":
                connected = False
                socket.close()
                break
            
            if msg.startswith("/query"): # afficher requête pour admin
                if ":" in msg:
                    print(Fore.RED + "Le format de la commande est incorrect !")
                else:
                    final_request = msg + ":" + username
                    socket.send(final_request.encode())
                
            if (msg.startswith("/accept") or msg.startswith("/refuse")) and not(msg == "/accept" or msg == "/refuse"): # accepter ou refuser une requête
                
                id_selected = msg.split(" ")[1]
                new_msg = msg.split(" ")[0]
                final_request = new_msg + ":" + username + ":" + id_selected
                socket.send(final_request.encode())
            
            if "/unsubscribe" in msg:
                room = "General"
                cls()
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
    """
    Recevoir un message du serveur et l'afficher
    
    Args:
        socket (socket): Le socket du client.
        host (str): L'adresse IP du serveur.
        
    Returns:
        None
        
    Raises:
        ConnectionClosedByServer : Si le serveur ferme la connexion de manière inattendue.
        KickedFromRoom : Si le client est kick du salon.
        ConnectionAbortedError : Si la connexion est interrompue par le serveur.
    """
    global room
    global connected
    global msg # récupérer le dernier msg envoyé par le client
    while connected:
        try:
            reply = socket.recv(1024).decode()
            print("\r\033[2K",end="")  # carriage return + clear line
            
            if reply.startswith("cmd:"):
                cls()
                reply = reply.split("cmd:")[1]
                if "alw:" in reply:
                    for a in reply.split(","):
                        if "alw:" in a:
                            print(Fore.GREEN + a.split("alw:")[1] + " (Unlocked)")
                        else:
                            print(Fore.RED + a + " (Locked)")
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                    
            elif reply.startswith("users:"): # le serveur renvoie la liste des utilisateurs
                reply = reply.split("users:")[1].split(",")
                cls()
                for user in reply:
                    if user == username:
                        print(Fore.GREEN + user + " (You)")
                    else:
                        print(Fore.YELLOW + user)
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                
                
            elif reply.startswith('jn:') and 'kick' in reply:
                    
                TimeKick = reply.split('time:')[1]
                
                reply = None
                
                
                raise KickedFromRoom(str(TimeKick))
                
            elif reply.startswith("jn:"): # le serveur renvoie la réponse du /join
                cls()
                reply = reply.split("jn:")[1]
                
                if "Succès" in reply:
                    room = reply.split(":")[1]
                    print(Fore.GREEN + f" Bienvenue dans le salon {room} !")
                else:
                    print(Fore.RED + reply)
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
            
            
                
            elif reply.startswith("query:"): # le serveur
                cls()
                reply = reply.split("query:")[1].replace("\'", "").split("!")
                for q in reply:
                    q = q.replace("[", "").replace("]", "").split(",") # pour changer le string avec les "[]" en vrai liste
                    
                    if int(q[-1]) == 0:
                        print(Fore.GREEN + f"ID: {q[0]} -> {q[1]} {q[2]} {q[3]}",sep = "\n")
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                
            elif reply.startswith("us:"): # le serveur renvoie la réponse du /unsubscribe
                cls()
                reply = reply.split("us:")[1]
                
                if "désabonné" in reply:
                    room = "General"
                    print(Fore.GREEN + f" Vous avez bien été désabonné du salon !")
                else:
                    print(Fore.RED + reply)
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                
            elif reply.startswith("fwd:"): # le serveur forward une réponse d'un client dans le même salon
                fwd_user, fwd_reply = reply.split("fwd:")[1].split(":")[0], reply.split("fwd:")[1].split(":")[1]
                print(Fore.LIGHTBLUE_EX + f"{fwd_user}: {Fore.RESET}{fwd_reply}", end="")
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                
            elif reply.startswith("old:"):# le serveur renvoie les anciens messages
                restore_old_messages(reply)
                print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
                reply = None
                
            
            print(f"server: ",reply, end="") if reply else None
            print('\033[1F',f'\n{username}@{room} $:', end="") if reply else None # descebdre le curseur et afficher le prompt
            
            if reply == "bye" or reply == "arret":
                connected = False
                socket.close()
                raise ConnectionClosedByServer('closed connection')
                break
            reply = None
        except ConnectionClosedByServer as err:
            print(Fore.GREEN + "\rVous avez bien été déconnecté du serveur")
            break
        except KickedFromRoom as err:
            print(Fore.RED + f"\rVous avez été kick du salon par le serveur jusque {str(err)}")
            break
        
        except ConnectionAbortedError as err:
            print(Fore.RED + "La connexion a été interrompue par le serveur") \
                if not msg == "bye" \
                    else print(Fore.GREEN + "\rVous avez bien été déconnecté du serveur")
            break
        else: 
            pass
        
    return 0

def restore_old_messages(payload):
    """
    Permet de restaurer les anciens messages du salon actuel.
    
    Args:
        payload (str): Les anciens messages du salon.

    Returns:
        None
        
    Raises:
        None (contrôlé par serveur)
    
    
    """
    all_messages = payload.split("old:")[1].split(",")
    
    # restaure les messages du salon actuel
    for message in all_messages:
        print(Fore.LIGHTBLUE_EX + f"{message.split(':')[0]}: {Fore.RESET}{message.split(':')[1]}".lstrip()) \
            if message.split(':')[0] != username \
                else print(f"you: {Fore.RESET}{message.split(':')[1]}".lstrip())
                
    return 0


def interactive(host):
    """
    Fonction permettant d'initier le mode interactif du client.
    
    Args:
        host (str): L'adresse IP du serveur.
        
    Returns:
        None
    
    Raises:
        None
    
    """
    global connected
    connected = True
    #print("Interactive mode", end="\n")
    #send(client_socket,host) # ne pas le mettre dans un thread pour qu'il puisse gérer activement l'input
    threading.Thread(target=receive, args=(client_socket,host)).start()
    send(client_socket,host) # ne pas le mettre dans un thread pour qu'il puisse gérer activement l'input
    #threading.Thread(target=send, args=(client_socket,host)).start()
    
    return 0 
def get_ip():
    """
    Fonction utilisant un socket afin d'initier une connexion vers 8.8.8.8
    et récupérer l'adresse IP de l'interface utilisée.
    
    Args:
        None
    
    Returns:
        str: L'adresse IP de l'interface.
        
    Raises:
        Exception: Si la connexion échoue.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0] # récupérer l'adresse ip de l'interface
    except Exception as e:
        pass
    finally:
        s.close()
    
    return str(ip)

# Cette fonction a été générée par chatgpt
def get_interface_name_by_ip(ip_address):
    """
    Fonction générée par ChatGPT permettant de récupérer nom 
    d'une interface active
    
    Args:
        ip_address (str): L'adresse IP de l'interface.
        
    Returns:
        str: Le nom de l'interface.
        
    Raises:
        None
    """
    try:
        # Utiliser socket pour résoudre le nom d'hôte associé à l'adresse IP
        hostname, _, _ = socket.gethostbyaddr(ip_address)

        # Utiliser psutil pour obtenir les informations sur les interfaces réseau
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address == ip_address or addr.address == hostname:
                    return interface

        # Si aucune correspondance n'est trouvée
        return None

    except (socket.herror, KeyError):
        # Gérer les erreurs en cas de résolution d'adresse IP ou si l'adresse IP n'est pas trouvée dans les interfaces
        return None
def handle_announcement(pkt):
    """
    Fonction permettant de chercher l'annoncement du serveur à travers le réseau
    sur une interface donnée et de récupérer l'adresse IP et le port du serveur.
    
    Args:
        pkt (packet): Le paquet reçu.
        
    Returns:
        None
        
    Raises:
        None
    """
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        load = pkt[Raw].load.decode('utf-8')
        if "Server announcement" in load:
            print("Received announcement:", load)
            server_ip = pkt[IP].src
            server_port = load.split(":")[2]
            print("Server IP:", server_ip)
            print("Server Port:", server_port)
            print("Connecting to host:", server_ip, "with port:", server_port, end="\n")
            host = server_ip
            port = int(server_port)
            
            main(server_ip, int(server_port))
            sys.exit(0)
   

if __name__ == "__main__":
    """
    Point d'entrée du programme client (si exécuté en script)
    
    Récupérer les arguments de la ligne de commande et lancer le programme client.
    
    Si search est activé:
        vérifier si le client s'exécute sur une machine virtuelle. Si ce n'est pas le cas, rechercher des serveurs sur le réseau local en utilisant des paquets UDP.
        Puis s'il y a un serveur trouvé, se connecter à celui-ci en utilisant l'adresse et le port.
    Sinon:
        se connecter au serveur en utilisant l'adresse et le port donnés en argument. (ou ceux par défaut)
    """
    
     # commun à tous les clients
    args = arg_parse()
    host = None
    port = None
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket personnalisé
    if args.search == True or args.search == 1:
        
        if os.name == 'nt':
            vm_check = True \
                if "virtualbox" in getResults('WMIC COMPUTERSYSTEM GET MODEL').lower() \
                    or getResults("WMIC BIOS GET SERIALNUMBER").split("\n")[1] == "0" \
                        else False # Vérifie si le client est dans une VM ou non.
        else:
            vm_check = True \
                if "virtualbox" in getResults('dmidecode -s system-product-name').lower() \
                    or getResults("dmidecode -s system-serial-number").split("\n")[1] == "0" \
                        else False # Vérifie si le client est dans une VM ou non.
            
        if not vm_check:
            c_iface = get_interface_name_by_ip(get_ip())
            print("searching for server...")
            client_ports = 9999
            filters = f"udp port {client_ports}"
            sniff(prn=handle_announcement, filter=filters, store=0, iface=c_iface, timeout=20, count=1)
            if host == None or port == None:
                print(Fore.RED + "Impossible de trouver le serveur, vérifiez que le serveur est bien lancé sur le réseau local.")
                sys.exit()
        else:
            print(Fore.RED + "Vous ne pouvez pas lancer le client en mode recherche depuis une machine virtuelle." + Fore.YELLOW + "\nIl est important de noter que vous devriez mettre le serveur sur cette VM et les clients sur des machines physiques.(pour que ça puisse fonctionner)")
            sys.exit()
    else:
    
        if len(sys.argv) > 1: # si le client donne un argument ou plus 
            print("Connecting to host: ", args.host, "with port: ", args.port)
        else:
            print("Connecting to default host and port (localhost:1234)")
        main(args.host, args.port) # lancer le client


