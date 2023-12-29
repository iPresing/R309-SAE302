"""
Cet extrait de code est une implémentation du serveur d'un application de chat. 
Il inclut des classes pour gérer les permissions utilisateurs, gérer les exceptions, et intéragir avec la base de donnée Mysql. 
Le serveur écoute les connexions entrantes, authentifie les utilisateurs, et leur permet d'envoyer et recevoir des messages dans différents salons de discussion.

La gestion des permissions se fait en grande partie localement, mais dès qu'il y a modification il y a restauration depuis la base de donnée Mysql.

L'utilisation de code ANSI permet de correctement positionner le terminal afin d'éviter de rencontrer des artéfacts visuels,
on ne peut malheureusement gérer tous ces artifacts.



Exemple d'utilisation:
python server.py --port 1234


Entrées:
- port: Le port sur lequel le serveur écoute les connexions entrantes.

Déroulement:
1. Le serveur créé un socket et le bind à lui-même et un port (spécifié en arguments).
2. Le serveur commence à écouter les connexions entrantes.
3. Quand un client se connecte, le serveur reçoit un payload contenant les informations suivantes:
- challenge: une suite logique permettant de vérifier authenticié du client
- username: le nom d'utilisateur du client
- password: le mot de passe du client
4. Le serveur vérifie les informations d'authentification en les comparant à une base de données MySQL.
5. Si les informations sont valides, le serveur ajoute le socket du client à un dictionnaire de clients connectés. (socket_list)
6. Le serveur démarre un nouveau thread pour gérer l'interaction du client.
7. Le client peut envoyer et recevoir des messages dans différents salons de discussion.
8. Le serveur stocke les messages dans une base de données MySQL pour une récupération future.
9. Le serveur diffuse les messages reçus à tous les clients dans le même salon de discussion.
10. Le serveur gère les commandes telles que rejoindre un salon, s'abonner à un salon, et expulser / bannir des utilisateurs.
11. Le serveur arrête le thread d'interaction et ferme le socket du client lorsque le client se déconnecte.    


Sorties:
- Messages reçus des clients sont diffusés à d'autres clients dans le même salon de discussion.
- Le serveur gère les commandes et met à jour les capacités de l'utilisateur et les salons autorisés en conséquence.
- Le serveur stocke les messages dans une base de données MySQL pour une récupération future.


"""
from _socket import *
import socket
from socket import socket
import threading
from colorama import init, Fore, Back, Style
from numpy import random
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os
import mysql.connector
from mysql.connector import Error
import argparse
import time
import logging
import psutil
from math import *
logging.getLogger("scapy").setLevel(logging.CRITICAL) # pour éviter les log de warning
from scapy.all import *
from scapy.all import conf
import datetime
import builtins as bt
import itertools
import dotenv


def animate():
    for c in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rVérifier adresse IP et si PORT disponible '+c)
        sys.stdout.flush()
        time.sleep(0.1)
        
    IP_host = get_ip()
    sys.stdout.write('\r -----Serveur démarré. en attente de clients-----\n')
    sys.stdout.write(f'Adresse IP du serveur: {IP_host}\n')
    sys.stdout.write(f'Port du serveur: {port}\n')


# gestion des droits utilisateurs
class user_capabilities(object):
    """
    Classe permettant de gérer localement les droits des utilisateurs.
    Ces droits sont stockés dans une base de donnée Mysql et sont restaurés dans le classe à chaque modification.
    
    
    Args:
        object: classe parente
        
    Attributes:
        username: le nom d'utilisateur
        allowed_room: les salons autorisés
        is_admin: les droits d'administrateur
        all_rooms: tous les salons disponibles
        current_room: le salon actuel
        
    Methods:
        __init__: constructeur de la classe
        __str__: méthode pour afficher les attributs de la classe
        __repr__: méthode pour afficher les attributs de la classe
        __eq__: méthode pour comparer les attributs de la classe
        __ne__: méthode pour comparer les attributs de la classe
        is_admin: méthode pour vérifier si l'utilisateur est administrateur
        username: méthode pour récupérer le nom d'utilisateur
        allowed_room: méthode pour récupérer les salons autorisés
        
    Raises:
        None   
        """
    
    
    
    all_rooms = ["General","Blabla","Comptabilité", "Informatique", "Marketing"]
    current_room = "General"
    def __init__(self, username, allowed_room, is_admin):
        """
        Constructeur de la classe user_capabilities
        
        Classe permettant de gérer localement les droits des utilisateurs.
        Ces droits sont stockés dans une base de donnée Mysql et sont restaurés dans le classe à chaque modification.
        
        
        Args:
            object: classe parente
            
        Attributes:
            username: le nom d'utilisateur
            allowed_room: les salons autorisés
            is_admin: les droits d'administrateur
            all_rooms: tous les salons disponibles
            current_room: le salon actuel
            
        Methods:
            __init__: constructeur de la classe
            __str__: méthode pour afficher les attributs de la classe
            __repr__: méthode pour afficher les attributs de la classe
            __eq__: méthode pour comparer les attributs de la classe
            __ne__: méthode pour comparer les attributs de la classe
            is_admin: méthode pour vérifier si l'utilisateur est administrateur
            username: méthode pour récupérer le nom d'utilisateur
            allowed_room: méthode pour récupérer les salons autorisés
            
        Raises:
            None   
        
        """
        self.__username = username
        self.__allowed_room = allowed_room
        self.__is_admin = is_admin
        
        
    @property
    def username(self):
        return self.__username
    
    @property
    def allowed_room(self):
        return self.__allowed_room
    
    @allowed_room.setter
    def allowed_room(self, value):
        self.__allowed_room = value
        
    @property
    def is_admin(self):
        return self.__is_admin
    
    @is_admin.setter
    def is_admin(self, value):
        self.__is_admin = value
        

    def __str__(self):
        return f"username: {self.username}, allowed_room: {self.allowed_room}, is_admin: {self.is_admin}"
    
    def __repr__(self):
        return f"username: {self.username}, allowed_room: {self.allowed_room}, is_admin: {self.is_admin}"
    
    def __eq__(self, other):
        return self.username == other.username and self.allowed_room == other.allowed_room

    def __ne__(self, other):
        return self.username != other.username or self.allowed_room != other.allowed_room

# exception permettant de prévenir de l'envoie d'un "bye" général
class LogoutBroadcast(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class IncorrectPassword(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class BannedUser(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class LimitConnectionIP(Exception):
    def __init__(self, message):
        super().__init__(message)



def arg_parse():
    """
    Fonction permettant de parser les arguments passés en ligne de commande
    
    Args:
        None
        
    Returns:
        args: les arguments passés en ligne de commande
        
    Raises:
        None
    """
    
    
    
    parser = argparse.ArgumentParser(description='Serveur de chat')
    parser.add_argument('--port', default=1234, type=int, help='Port sur lequel le serveur écoute les connexions entrantes')
    #args = parser.parse_args()
    return parser.parse_args()
      
        
# Configuration du serveur
#host = "0.0.0.0"
#port = arg_parse().port -> déplace dans __main__
global connected
global socket_list
global user_caps
connected = False
socket_list = {} # dictionnaire contenant les sockets des clients
user_caps = {} # dictionnaire contenant les droits des utilisateurs
#key = os.environ['AES_KEY'].encode() # récupérer depuis les variables d'environnements
#iv = os.environ['AES_IV'].encode() #récupérer depuis les variables d'environnements
#mysql_passwd = os.environ['MYSQL_PASSWD'] #récupérer depuis les variables d'environnements

# récupère key, iv, mysql_passwd depuis .env
dotenv.load_dotenv()
key = os.getenv('AES_KEY').encode() # récupérer depuis les variables d'environnements
iv = os.getenv('AES_IV').encode() #récupérer depuis les variables d'environnements
mysql_passwd = os.getenv('MYSQL_PASSWD') #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)

# Liste de pseudos par défaut
default_pseudo =  ["Nosferatu","BlackBird","Pleiades","Hyades","Undertaker","BloodyReina","Wehrwolf","LaughingFox","SnowWitch"\
    ,"Gunslinger","Sagittarius","Cyclops","Melusine","Bluebell","Verethragna","Hualien","Milan","Baldanders","Catoblepas","Banshee"\
    ,"Grimalkin","Bandersnatch","Jabberwock","Dullahan","Kirschblüte","BlackDog","Falke","Fafnir","Helianthus","Walpurgis","Griffin",\
    "Manticore","Artemis","Cato'Nine","MarchHare","Sirius","Leukosia","Gunmetalstorm","LaBete","Dendroaspis","Burnt Tayl","Gladiator",\
    "Argos","Vulture","Estoc","Grimoire","Gungnir","GaeBolg","Excalibur","Durandal","ClaiomhSolais",\
"Caladbolg","Balmung","AmeNoMurakumo"]

def cls():
    """
    Fonction permettant de nettoyer la console
    
    Args:
        None
        
    Returns:
        None
        
    Raises:
        None
    
    """
    os.system('cls' if os.name=='nt' else 'clear')

# récupérer le pseudo à partir de la valeur "socket"
def username(dictionary, value):
    """
    Une des méthodes permettant de récupérer le pseudo à partir de la valeur "socket"
    en parcourant un dictionnaire (normalement socket_list)
    
    Args:
        dictionary: le dictionnaire à parcourir
        value: la valeur à récupérer
        
    Returns:
        key: la clé correspondant à la valeur
        or
        None: si la valeur n'est pas trouvée
    
    
    """
    for key, val in dictionary.items():
        if val == value:
            return key
    return None  # Ou retourner None





def encrypt(payload): # pour automatiser encryption
    """
    Encrypter un payload donné en utilisant l'algorithme de chiffrement AES.
    
    Args:
        payload (bytes): Le payload à chiffrer.

    Returns:
        bytes: Le payload chiffré.
    """  
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))

def decrypt(payload): # pour automatiser decryption
    """
    Decrypter un payload donné en utilisant l'algorithme de chiffrement AES.
    
    Args:
        payload (bytes): Le payload à déchiffrer.
    
    Returns:
        str: Le payload déchiffré.
    
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(payload), AES.block_size).decode()


def user_sql_handler(user, password, socket, ip_address):
    
    ip_address = ip_address.strip('()\'').split(',')[0].strip('\'')
    """
    Fonction essentielle permettant de gérer l'authentification des utilisateurs.
    Elle gère à la fois la connexion et l'inscription des utilisateurs.
    
    Les mots de passes ne sont pas entrés en clair dans la base de données, ils sont encryptés en utilisant l'algorithme SHA256.
    Une limite de connexion est imposée par adresse ip (2 comptes max par ip).
    Une fois la connexion établie, les informations de l'utilisateur sont restaurées depuis la base de données et insérées dans un dictionnaire (user_caps).
    
    Args:
        user: le nom d'utilisateur
        password: le mot de passe
        socket: le socket du client
        ip_address: l'adresse ip du client
        
    Returns:
        True: si l'utilisateur est authentifié
        False: si l'utilisateur n'est pas authentifié
        
    Raises:
        Error: si une erreur de connexion à la base de données est détectée
        IncorrectPassword: si le mot de passe est incorrect
        LimitConnectionIP: si la limite de connexion par ip est atteinte
        BannedUser: si l'utilisateur est banni
    
    """
    global current_user
    password_salt = encrypt(password.encode()) + encrypt(user.encode())
    password = hashlib.sha256(password_salt).hexdigest()
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='seleenix',
            user='root',  # récupéré depuis var d'environnement
            password=mysql_passwd  # récupéré depuis var d'environnement
        )
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (user, password))

        # Utilisez fetchone() pour récupérer une ligne du résultat
        row = cursor.fetchone()

        if row:
            #print(row)
            
            # requête spéciale permettant de vérifier si l'utilisateur est banni dans la table sanction
            special_query = "SELECT * FROM sanction WHERE username = %s AND type = %s"
            cursor.execute(special_query, (user, "ban"))
            special_row = cursor.fetchone()
            
            # requête spéciale permettant de vérifier si l'utilisateur est banni dans la table sanction, ou si la date de fin de sanction est dépassée
            
            if special_row:
                raise BannedUser(f"Vous avez été banni, veuillez contacter l'administrateur{str(':') + str(special_row[3]) if special_row[3] else ''}")
            else:
                pass
            
            
            #requête spéciale permettant de vérifier si l'utilisateur est kické dans la table sanction
            special_query2 = "SELECT * FROM sanction WHERE username = %s AND type = %s"
            cursor.execute(special_query2, (user, "kick"))
            special_row2 = cursor.fetchone()
            
            if special_row2:
                # convertir la date en time stamp
                time_kick = datetime.datetime.timestamp(special_row2[6])
                if floor(time_kick) > floor(time.time()) and special_row2[2] == 'ALL':
                    raise BannedUser(f"Vous avez été banni, veuillez contacter l'administrateur{str(':') + str(special_row[3]) if special_row[3] else ''}")
                else:
                    pass
                    
        
            #current_user = user_capabilities(row[0], row[3], row[2])
            user_caps[socket] = user_capabilities(row[0], row[3], row[2])
            print("Utilisateur trouvé, restauration de ses données...")
            return True
        else:
            # nouvelle requête pour vérifier occurence de l'ip si > 1 alors pass
            query = "SELECT * FROM users WHERE ip = %s OR ip = %s"
            cursor.execute(query, (ip_address,'0.0.0.0'))
            #print(ip_address)
            
            ip_row = cursor.fetchall()
            print(ip_row)
            if len(ip_row) > 1: # 2 comptes max par ip
                raise LimitConnectionIP("Vous avez atteint la limite de connexion sur cette adresse ip")
            else:     
                second_query = "SELECT * FROM users WHERE username = %s"
                cursor.execute(second_query, (user,))
                if cursor.fetchone():
                    raise IncorrectPassword("Utilisateur trouvé, mais le mot de passe est incorrect")
                else:
                    print("Utilisateur non trouvé, création d'un nouvel utilisateur...")
                    cursor.execute("INSERT INTO users (username, password, allowed_room, ip) VALUES (%s, %s, %s, %s)", (user, password, str("General"), ip_address))
                    connection.commit()
                    user_caps[socket] = user_capabilities(user, str("General"), 0) # pour nouveau utilisateur
                    #user_caps[socket] = user_capabilities(user, password, str("General")) # pour nouveau utilisateur 
                    return True
    except Error as e:
        print("Erreur de connexion à la base de données", e)
    except IncorrectPassword as e:
        #socket.send(f"{e}".encode())   
        #print("Compta banni")
        print(e)
        socket.close()
        return False
    except LimitConnectionIP as e:
        #socket.send(f"{e}".encode())   
        #print("Compta banni")
        print(e)
        socket.close()
        return False
    
    except BannedUser as e:
        socket.send(f"{e}".encode())   
        print("Compta banni")
        socket.close()
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            
def update_userinfo_sql(user, value, reason, socket):
    """
    Fonction essentielle permettant la mise à jour des informations dans la base de données suite à l'éxécution de commandes.
    Pour aller plus loin, elle permet de mettre à jour le contexte autours des utilisateurs (salons autorisés, droits d'administrateur, etc...)
    
    Args:
        user: le nom d'utilisateur
        value: la valeur à mettre à jour
        reason: la raison de la mise à jour
        socket: le socket du client
        
    Returns:
        None
        
    Raises:
        Exception: si la raison n'est pas valide (upgrade, roomupdate, password, roomdowngrade, kick, ban, query_insert, query_update)
    
    """
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='seleenix',
            user='root',  # récupéré depuis var d'environnement (pas si sensible)
            password=mysql_passwd  # récupéré depuis var d'environnement (exemple de mot de passe)
        )
        cursor = connection.cursor()
        if reason == "upgrade":
            query = "UPDATE users SET is_admin = %s WHERE username = %s"
            cursor.execute(query, (value, user))
            user_caps[socket].is_admin = value
            connection.commit()
        elif reason == "roomupdate":
            query = "UPDATE users SET allowed_room = %s WHERE username = %s"
            user_caps[socket].allowed_room += "," + value
            value = user_caps[socket].allowed_room
            cursor.execute(query, (value, user))
            connection.commit()
        elif reason == "password":
            query = "UPDATE users SET password = %s WHERE username = %s"
            cursor.execute(query, (value, user))
            connection.commit()
        elif reason == "roomdowngrade":
            query = "UPDATE users SET allowed_room = %s WHERE username = %s"
            user_caps[socket].allowed_room = value
            cursor.execute(query, (value, user))
            connection.commit()
            
        elif reason.startswith("query_insert"):
            reason = reason.split(":")[1] if "!" in reason else reason
            if "!" in reason:
                type, reason_query = reason.split("!")[0], reason.split("!")[1] # récupérer type sanction et le motif
            else:
                type = reason
                reason_query = None
                
            if user_caps[socket].is_admin == 1 or "server" in reason_query:
                is_accept = 1
            else:
                is_accept = 0
                
            rooms = value
                
            query = "INSERT INTO query (username, type, rooms, reason, is_accept) VALUES (%s, %s, %s, %s, %s)" \
                if reason_query else "INSERT INTO query (username, type, rooms, is_accept) VALUES (%s, %s, %s, %s)"
                
            if reason_query:
                cursor.execute(query, (user, type, rooms, reason_query, is_accept))
            else:
                cursor.execute(query, (user, type, rooms, is_accept))
            connection.commit()
                
        elif reason.startswith("query_update"):
            id, update_value = value.split(":")[0], value.split(":")[1]
            
            
            query = "UPDATE query SET is_accept = %s WHERE id = %s"
            cursor.execute(query, (update_value, id))
            connection.commit()
            
            # récupérer le champs type de query et crafter la réponse à envoyer
            query = "SELECT * FROM query WHERE id = %s"
            cursor.execute(query, (id,))
            row = cursor.fetchone()
            if row:
                if row[2] == "subscribe":
                    if row[5] == 1:
                        
                        target_socket = socket_list[row[1]]
                        
                        update_userinfo_sql(row[1], row[3], "roomupdate", target_socket)
                        target_socket.send(b'scb:' + str("Votre demande a été acceptée").encode())
                    else:
                        target_socket.send(b'scb:' + str("Votre demande a été refusée ou vous ne disposer pas des droits").encode())
                else:
                    pass
                
        elif reason.startswith("ban"):
            if ":" in reason:
                type, reason_k = reason.split(":")[0], reason.split(":")[1] # récupérer type sanction et le motif
            else:
                type = reason
                reason_k = None
                
            query = "INSERT INTO sanction(username,reason,type) VALUES (%s, %s, %s)" \
                if reason_k else "INSERT INTO sanction(username,type) VALUES (%s, %s)"
                
            if reason_k:
                cursor.execute(query, (user, reason_k, type))
            else:
                cursor.execute(query, (user, type))
            connection.commit()
            
            
            
            
        elif "kick" in reason:
            if ":" in reason:
                type, reason_k = reason.split(":")[0], reason.split(":")[1] # récupérer type sanction et le motif
            else:
                type = reason
                reason_k = None # pas de motif donné (non obligatoire)

            room = value.split("!")[0]
            date_debut = value.split("!")[1]
            date_final = value.split("!")[2]
            
            query = "INSERT INTO sanction(username,rooms,reason,type,start_date,end_date) VALUES (%s, %s, %s, %s, %s, %s)" \
                if reason_k else "INSERT INTO sanction(username,rooms,type,start_date,end_date) VALUES (%s, %s, %s, %s, %s)"

            if reason_k:
                cursor.execute(query, (user, room, reason_k, type, date_debut, date_final))
            else:
                cursor.execute(query, (user, room, type, date_debut, date_final))
            connection.commit()
        
        else:
            raise Exception("La raison n'est pas valide (upgrade, roomupdate, password, roomdowngrade, kick, ban, query_insert, query_update)")
    except Exception as e:
        print(e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()    
            
            
# Fonction pour envoyer des messages
def Send(socket, host):
    """
    Fonction permettant d'envoyer des messages.
    Elle gère également les commandes administrateurs et les requêtes sql.
    
    Args:
        socket: le socket du client
        host: l'hôte du serveur
        
    Returns:
       None
        
    Raises:
        ConnectionResetError: si la connexion est interrompue par le client
        OSError: si le socket est fermé
        LogoutBroadcast: si le serveur envoie un message de déconnexion général
        Exception: si la commande n'est pas valide    
    """
    #global hostup
    global connected
    global socket_list
    hostup = True
    
    while hostup:
        
        #enlever du dictionnaire socket_list les sockets [closed]
        for user_selected, socket_selected in list(socket_list.items()): # on utilise list pour éviter les erreurs de modification de taille 
            if bt.type(socket_selected) == str: # ça veut dire que le socket est fermé
                user_selected, socket_selected = socket_list.popitem()
            else:
                pass
                     
        try:    
            msg = input(f"server@{host} $:") 
            print("\033[1A\033[2K", end="")  # up + clear line
            print(f"you: {msg}") if msg else None
            if len(socket_list) > 1 and msg == "bye": # dans le cas où il y a plusieurs clients
                raise LogoutBroadcast("Attention vous vous apprêtez à envoyer un message de déconnexion à tous les clients")
            else:
                condition = ["/deop" in msg,"/op" in msg, msg == "bye", "/kick" in msg, "/ban" in msg, msg == "arret", msg == "", msg.startswith("/")]
                if any(condition): 
                    pass
                else:
                    if len(socket_list) > 1:
                        forwarded = False
                        
                        while not forwarded:
                            # envoyer à tous les clients
                            try:
                                for user in socket_list.values():
                                    if bt.type(user) == str:# donc fermé
                                        pass
                                    else:
                                        user.send(msg.encode()) if msg else None
                                forwarded = True
                            except OSError as err:
                                
                                # enlever de socket_list si le socket est fermé
                                #bugged_socket = user
                                #user = username(socket_list, bugged_socket)
                                #user, bugged_socket = socket_list.popitem()
                                print(Fore.RED + f"Le socket {user} n'existe plus", end=f'\n{Fore.RESET}')
                                pass
                            
                            except AttributeError: # si le socket est fermé (devient un str)
                                # enlever de socket_list si le socket est fermé
                                #bugged_socket = user
                                #user = socket_list[bugged_socket]
                                #user, bugged_socket = socket_list.popitem()
                                print(Fore.RED + f"Le message n'a pas été envoyé...", end=f'\n{Fore.RESET}')
                                pass
                            else:
                                pass
                    else:
                        socket.send(msg.encode()) if msg else None
        except ConnectionResetError:
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
                    target_socket = socket_list[f"{username}"] # essaie de récupérer le socket avec le username
                except KeyError as err:
                    print(Fore.RED + f"Le pseudo {username} n'existe pas \n ou l'utilisateur n'est pas connecté", end=f'\n{Fore.RESET}')
                    pass
                else:
                    target_socket.send("bye".encode())
                    username, target_socket = socket_list.popitem()
                    hostup = False
                   
            if "/kick" in (msg_d := msg.split(" ")):
                
                time_delimiter = ["h", "m"]
                
                type = "kick" 
                
                try:
                    if not msg_d[1] in socket_list.keys():
                        print(Fore.RED + f"Le pseudo {msg_d[1]} n'existe pas", end=f'\n{Fore.RESET}')
                        
                    elif not msg_d[2] in user_capabilities.all_rooms and msg_d[2] != "ALL":
                        print(Fore.RED + f"Le salon {msg_d[2]} n'existe pas", end=f'\n{Fore.RESET}')
                        
                    else:
                        user = msg_d[1]
                        rooms = msg_d[2]
                        reasons = msg_d[4] if len(msg_d) > 4 else None
                        if not time_delimiter[0] in msg_d[3]:
                                msg_d[3] = "0h" + msg_d[3]
                        elif not time_delimiter[1] in msg_d[3]:
                            msg_d[3] = msg_d[3] + "0m"
                        for a in time_delimiter:
                            msg_d[3] = msg_d[3].replace(a, ",")
                        else:
                            
                            time_matrix = msg_d[3].split(",")
                            if time_matrix[-1] == "": # dans le cas où on a 1h, 1h30m etc...
                                time_matrix.pop(-1)
                            
                            time_debut = floor(time.time())
                            time_fin =  time_debut + sum([int(a) * int(b) for a,b in zip(time_matrix,[3600,60,1])])
                            date_debut = datetime.datetime.fromtimestamp(time_debut)
                            date_fin = datetime.datetime.fromtimestamp(time_fin)
                            
                                         
                            update_userinfo_sql(user, f'{rooms}!{date_debut}!{date_fin}'\
                                , f"{f'kick:{reasons}' if reasons else type}"\
                                    , socket_list[user] )
                            
                            # log dans query_insert
                            update_userinfo_sql(user, f"{rooms}", f"query_insert:{type}!server", socket_list[user])  
                            if rooms == 'ALL':
                                socket_list[user].send(f'bye'.encode())
                                user, socket_list[user] = socket_list.popitem()
                                #hostup = False
                                
                            elif rooms == user_caps[socket_list[user]].current_room:
                                user_caps[socket_list[user]].current_room = "General"
                                socket_list[user].send(f"jn: Succès:General".encode())
                            else:
                                socket_list[user].send(f"jn: Succès:General".encode())
                                
                except Exception:
                    print(Fore.RED,"Le format de la commande est incorrect :\nex: /kick [pseudo] [rooms|ALL] 1h30 [reasons]", end=f"\n{Fore.RESET}" )
            if msg.startswith("/ban"):
                msg_d = msg.split(" ")
                
                type = "ban"
                
                try:
                    if not msg_d[1] in socket_list.keys():
                        print(Fore.RED + f"Le pseudo {msg_d[1]} n'existe pas", end=f'\n{Fore.RESET}')
                        raise Exception
                    else:
                        user = msg_d[1]
                        reasons = msg_d[2] if len(msg_d) > 3 else None
                        
                        update_userinfo_sql(user, None\
                                , f"{f'ban:{reasons}' if reasons else 'ban'}"\
                                    , socket_list[user] )
                        
                        # log dans query_insert 
                        update_userinfo_sql(user, f"{user_caps[socket_list[user]].all_rooms}", f"query_insert:{type}!server", socket_list[user])
                        
                        socket_list[user].send(f'bye'.encode())
                        user, socket_list[user] = socket_list.popitem()
                        #hostup = False
                    
                except Exception:
                    print(Fore.RED,"Le format de la commande est incorrect :\nex: /ban [pseudo] [reasons](optional)", end=f"\n{Fore.RESET}" )
            if msg.startswith("/unban"):
                msg_d = msg.split(" ")
                
                type = "ban"
                
                try:
                    user = msg_d[1]
                    reasons = msg_d[2] if len(msg_d) > 3 else None
                    
                    # bloc try except pour enlever la sanction si l'utilisateur est banni
                    try:
                        connection = mysql.connector.connect(
                            host='localhost',
                            database='seleenix',
                            user='root',  # récupéré depuis var d'environnement
                            password=mysql_passwd  # récupéré depuis var d'environnement
                        )
                        cursor = connection.cursor()
                        query = "DELETE FROM sanction WHERE username = %s AND type = %s"
                        cursor.execute(query, (user, type))
                        connection.commit()
                    except Error as e:
                        print("Erreur de connexion à la base de données", e)
                    finally:
                        if connection.is_connected():
                            cursor.close()
                            connection.close()
                    
                except Exception:
                    print(Fore.RED,"Le format de la commande est incorrect :\nex: /unban [pseudo]", end=f"\n{Fore.RESET}" )
            
            
            if msg == "/kill":
                
                for a_socket in socket_list.values():
                    a_socket.send(f"bye".encode())
                    a_socket.close()
                    
                hostup = False
                server_socket.close()
                connected = False
                break
            if msg.startswith("/op"):
                username = msg.split(" ")[1]
                update_userinfo_sql(username, 1, "upgrade", socket)
                
                
            if msg.startswith("/deop"):
                username = msg.split(" ")[1]
                update_userinfo_sql(username, 0, "upgrade", socket)
                
            if msg.startswith("/users"):
                available_users = [a for a in socket_list.keys()]
                cls()
                for user in available_users:
                    print(Fore.GREEN + user + f" ({user_caps[socket_list[user]].current_room})", end=f'\n{Fore.RESET}')
                print(f'\nserver@{host} $:', end="") if msg else None
                
            if msg.startswith("/accept") or msg.startswith("/refuse"):
                if len(msg.split(" ")) > 1:
                    value_send = msg.split(" ")[1] + ":" + str(1 if msg.startswith("/accept") else 0)
                    update_userinfo_sql(None, value_send, "query_update", socket) # le user et socket correspondants seront récupérés suite à une requête sql
                    
                    # si le message contenait un /refuse alors supprimer la requête de la base de donnée
                    if msg.startswith("/refuse"):
                        
                        try:
                            connection = mysql.connector.connect(
                                host='localhost',
                                database='seleenix',
                                user='root',  # récupéré depuis var d'environnement
                                password=mysql_passwd  # récupéré depuis var d'environnement
                            )
                            cursor = connection.cursor()
                            query = "DELETE FROM query WHERE id = %s"
                            cursor.execute(query, (msg.split(" ")[1],))
                            connection.commit()
                        except Error as e:
                            print("Erreur de connexion à la base de données", e)
                        finally:
                            if connection.is_connected():
                                cursor.close()
                                connection.close()
                    
                else:
                    print(Fore.RED + "La commande n'est pas valide, veuillez réessayer\nsyntaxe : /accept [id]", end=f'\n{Fore.RESET}')
                
            if msg.startswith("/query"):
                # afficher toutes les query de la table query
                try:
                    connection = mysql.connector.connect(
                        host='localhost',
                        database='seleenix',
                        user='root',  # récupéré depuis var d'environnement
                        password=mysql_passwd  # récupéré depuis var d'environnement
                    )
                    cursor = connection.cursor()
                    query = "SELECT * FROM query"
                    cursor.execute(query)
                    # Utilisez fetchone() pour récupérer une ligne du résultat
                    row = cursor.fetchone()
                    while row:
                        print(row)
                        row = cursor.fetchone()
                except Error as e:
                    print("Erreur de connexion à la base de données", e)
                
            if "/unsubscribe" in (msg_d:= msg.split(" ")):
                if len(msg_d) > 1:
                    username_s = msg.split(" ")[1]
                    room = msg.split(" ")[2]
                    
                    target_socket_s = socket_list[f"{username_s}"]
                    
                    if user_caps[target_socket_s].current_room == room: # pour éviter des conflits (forcé côté client également)
                            user_caps[target_socket_s].current_room = "General"
                    else:
                        pass
                    new_room = ",".join([a for a in user_caps[target_socket_s].allowed_room.split(",") if not a == room])

                else:
                    room = None
                    print(Fore.RED + "La commande n'est pas valide, veuillez réessayer\nsyntaxe : /unsubscribe [user] [room]", end=f'\n{Fore.RESET}')
                if (room in user_caps[target_socket_s].allowed_room):
                    update_userinfo_sql(username_s, new_room, "roomdowngrade", target_socket_s)
                    target_socket_s.send(f"us: Vous avez été désabonné de la room {room}".encode())
                else:
                    print(Fore.RED + "L'utilisateur ciblé n'est pas inscrit à ce salon", end=f'\n{Fore.RESET}')
                
            msg = None
    socket.close()

# Fonction pour recevoir des messages
def receive(socket, host):
    """
    Fonction permettant de gérer la réception de messages.
    Elle gère également les commandes administrateurs et les requêtes sql.
    Elle gère aussi le broadcast des messages reçus aux utilisateurs connectés (dans le même salon).
    
    Elle enregistre les messages dans la base de données.
    
    Args:
        socket: le socket du client
        host: l'hôte du serveur
    
    Returns:
        None
        
    Raises:
        ConnectionResetError: si la connexion est interrompue par le client
        ConnectionAbortedError: si la connexion est interrompue par le serveur
        OSError: si le socket est fermé
        Exception: si la commande n'est pas valide
        AttributeError: si le socket est fermé (devient string)

    """

    global connected
    hostup = True
    
    while hostup:
        try:
            reply = socket.recv(1024).decode()
        except ConnectionResetError:
            
            #enlever username et socket de socket_list
            socket_list[socket], socket = socket_list.popitem()
            
            hostup = False
            print("La connexion a été interrompue par le client")
            socket.close() if bt.type(socket) != str else None
            break
        except ConnectionAbortedError:
            
            #enlever username et socket de socket_list
            socket_list[socket], socket = socket_list.popitem()
            
            hostup = False
            print("(rcv)Le serveur a fermé sa connexion")
            socket.close() if bt.type(socket) != str else None
            break
        
        except OSError:
            #enlever username et socket de socket_list
            socket_list[socket], socket = socket_list.popitem()
            
            #hostup = False
            print("(rcv)Le socket a été fermé")
            socket.close() if bt.type(socket) != str else None
            pass
        except AttributeError: # quand le socket se ferme et devient un string
            pass
        else:
            # liste qui contient tous les entêtes de réponses à une commande
            # elle est utilisée pour éviter que les clients envoient des fausses réponses à une commande
            list_header = [reply.startswith("fwd"), reply.startswith("us"), reply.startswith("jn"), reply.startswith("scb"), reply.startswith("query"), reply.startswith("cmd")]
            forward_condition = not(any(list_header))
            
            
            print("\033[2K", end="\r ")  # carriage return + clear 
            
            print(f"{username(socket_list,socket)}: {reply}", end="") if not "/" in reply and reply else None
            
            
            
            if not "/" in reply and not reply == "bye" and not reply == "/kill" and reply and forward_condition:
                
                # cette section servira à l'insertion des messages dans la table channel de la base de donnée
                m_username = user_caps[socket].username
                m_rooms = user_caps[socket].current_room
                id = user_caps[socket].all_rooms.index(m_rooms)
                content = reply
                forwarded = False
                
                while not forwarded:
                    try:
                        # Cette variable contient les sockets des clients qui sont dans la même room que le client actuel
                        target_list = [a if \
                            (user_caps[a].current_room == user_caps[socket].current_room)  \
                                and a != socket and type(a) != str else None for a in socket_list.values()]
                    except KeyError as err:
                        print(Fore.RED + f"Un message n'a pas été envoyé", end=f'\n{Fore.RESET}')            
                        #print(Fore.RED + f"Le user {err} n'existe plus", end=f'\n{Fore.RESET}')
                        pass
                
                    for user_target in target_list:
                        try:
                            user_target.send(f"fwd:{username(socket_list,socket)}:{reply}".encode()) \
                                if user_target else None
                            forwarded = True
                        except OSError as err:        
                            # enlever de socket_list si le socket est fermé
                            bugged_socket = user_target
                            user_target = username(socket_list, bugged_socket)
                            user_target, bugged_socket = socket_list.popitem()
                            #print(Fore.RED + f"Le socket {user_target} n'existe plus", end=f'\n{Fore.RESET}')
                            pass
                        else:
                            pass
                
                
                try: # tentative d'insertion dans la base de données
                    connection = mysql.connector.connect(
                        host='localhost',
                        database='seleenix',
                        user='root',  # récupéré depuis var d'environnement
                        password=mysql_passwd  # récupéré depuis var d'environnement
                    )
                    cursor = connection.cursor()
                    query = "INSERT INTO channel (id, rooms, users, content) VALUES (%s, %s, %s, %s)"
                    cursor.execute(query, (id, m_rooms, m_username, content))
                    connection.commit()
                
                
                except Error as e:
                    print("Erreur de connexion à la base de données", e)
                finally:
                    if connection.is_connected():
                        cursor.close()
                        connection.close()
                
            # Vérifie si la réponse commence par "query:" et que l'utilisateur contenu dans la réponse est un administrateur
            # Le premier dictionnaire socket_list est utilisé pour récupérer le socket de l'administrateur
            # Le second dictionnaire user_caps est utilisé pour récupérer les droits de l'administrateur (via la classe user_capabilities)
            
            if reply.startswith("/query:") and (user_caps[socket_list[q_user:=reply.split(":")[1]]].is_admin \
                if reply.split(":")[1] in socket_list.keys() else None):

                try:
                    connection = mysql.connector.connect(
                        host='localhost',
                        database='seleenix',
                        user='root',  # récupéré depuis var d'environnement
                        password=mysql_passwd  # récupéré depuis var d'environnement
                    )
                    cursor = connection.cursor()
                    query = "SELECT * FROM query"
                    cursor.execute(query)
                    
                    all = cursor.fetchall()
                    
                    all = "!".join([str(list(a)) for a in all])

                    socket.send(f"query:{all}".encode())
                   
                except Error as e:
                    print("Erreur de connexion à la base de données", e)
                finally:
                    if connection.is_connected():
                        cursor.close()
                        connection.close()
                        
            if (reply.startswith("/accept:") or reply.startswith("/refuse:")) and user_caps[q_socket:=socket_list[q_user:=reply.split(":")[1]]].is_admin:
                value_send = reply.split(":")[2] + ":" + str(1 if reply.startswith("/accept") else 0)
                
                update_userinfo_sql(None, value_send, "query_update", q_socket) # le user et socket correspondants seront récupérés suite à une requête sql

                # si le message contenait un /refuse alors supprimer la requête de la base de donnée
                time.sleep(1)
                if reply.startswith("/refuse"):
                    try:
                        connection = mysql.connector.connect(
                            host='localhost',
                            database='seleenix',
                            user='root',  # récupéré depuis var d'environnement
                            password=mysql_passwd  # récupéré depuis var d'environnement
                        )
                        cursor = connection.cursor()
                        query = "DELETE FROM query WHERE id = %s"
                        cursor.execute(query, (reply.split(":")[2],))
                        connection.commit()
                    except Error as e:
                        print("Erreur de connexion à la base de données", e)
                    finally:
                        if connection.is_connected():
                            cursor.close()
                            connection.close()
            
            if reply == "/kill":
                reply = None
                pass
            if reply == "/rooms":
                # Cette variable contient les rooms disponibles et ajoute le flag alw: si le client possède un accès à la room 
                available_rooms = ",".join([f"alw:{a}" if a in user_caps[socket].allowed_room \
                    else a for a in user_caps[socket].all_rooms ]) 
                socket.send(b'cmd:' + str(available_rooms).encode())
                
            if reply == "/users":
                # Cette variable contient les users connectés et ajoute le flag alw: si le client possède un accès à la room 
                available_users = ",".join([a for a in socket_list.keys()]) 
                socket.send(b'users:' + str(available_users).encode())
                
            if "/subscribe" in reply:
                if len(reply.split(" ")) > 1:
                    room = reply.split(" ")[1]
                else:
                    room = None
                    
                print(room)
                
                if (room in user_caps[socket].all_rooms and user_caps[socket].is_admin == 1) or (room == "Blabla"):
                    update_userinfo_sql(username(socket_list,socket), room, f"query_insert:subscribe!server", socket)
                    update_userinfo_sql(username(socket_list,socket), room, "roomupdate", socket) \
                        if not room in user_caps[socket].allowed_room else None
                    socket.send(b'scb:' + str("Votre demande a été acceptée").encode())
                    
                elif (room in user_caps[socket].all_rooms):
                    cls()
                    # log dans query_insert
                    update_userinfo_sql(username(socket_list,socket), room, f"query_insert:subscribe!{room}", socket)
                      
                else:
                    socket.send(b'scb:' + str("Votre demande a été refusée ou vous ne disposer pas des droits").encode())
                
            if "/join" in reply:
                if len(reply.split(" ")) > 1:
                    room = reply.split(" ")[1]
                else:
                    room = None
                
                if (room in user_caps[socket].allowed_room):
                    
                    # faire une requête sql vers la table sanction et vérifie si le user n'est pas kick du salon
                    try:
                        connection = mysql.connector.connect(
                            host='localhost',
                            database='seleenix',
                            user='root',  # récupéré depuis var d'environnement
                            password=mysql_passwd  # récupéré depuis var d'environnement
                        )
                        cursor = connection.cursor()
                        query = "SELECT * FROM sanction WHERE username = %s AND rooms = %s AND type = %s"
                        cursor.execute(query, (user_caps[socket].username, room, "kick"))
                        row = cursor.fetchone()
                        if row:
                            date_fin_v1 = row[6]
                            date_fin = date_fin_v1.timestamp()
                            if date_fin > time.time():
                                raise Exception(str(date_fin_v1))
                            else:
                                pass
                        else:
                            pass
                    except Exception as e:
                        socket.send(f"jn: Vous avez été kick de la room {room} time:{e}".encode())
                        
                        continue
                        
                    
                    
                    user_caps[socket].current_room = room
                    socket.send(f"jn: Succès:{room}".encode())
                    restore_old_messages(socket)
                else:
                    socket.send(f"jn: Vous ne disposez pas d'accès au salon {room}, veuillez vous y souscrire..".encode())
                    
            if "/unsubscribe" in reply: # à update pour sélectionner le bon user
                if len(reply.split(" ")) > 1:
                    username_r = username(socket_list, socket)
                    room = reply.split(" ")[1]
                    
                    target_socket = socket
                    
                    if user_caps[target_socket].current_room == room: # pour éviter des conflits (forcé côté client également)
                        user_caps[target_socket].current_room = "General"
                    else:
                        pass
                    
                    new_room = ",".join([a for a in user_caps[target_socket].allowed_room.split(",") if not a == room])
                else:
                    room = None
                
                if (room in user_caps[target_socket].allowed_room):
                    update_userinfo_sql(username_r, new_room, "roomdowngrade", target_socket)
                    target_socket.send(f"us: Vous avez été désabonné de la room {room}".encode())
                else:
                    target_socket.send(f"us: Vous ne disposez pas d'accès au salon {room}, veuillez vous y souscrire..".encode())
                    
            if reply.startswith("/"): # commande sans output
                print(f'server@{host} $:', end="")
            elif reply and not reply.startswith('/'):
                print(f'\nserver@{host} $:', end="")
            else:
                None
            reply = None
    socket.close() if type(socket) != str else None # le si le type est str ça signifie que le socket est déjà fermé


def restore_old_messages(socket):
    """
    Cette fonction permet de récupérer la totalité des messages d'un salon donné.
    Elle est utilisée lorsqu'un utilisateur rejoint un salon.
    Elle récupère les messages depuis la base de données.
    Et les envoie à l'utilisateur.
    
    Args:
        socket: le socket du client
    
    Returns:
        None
        
    Raises:
        Error: si la connexion à la base de données échoue
    
    """
    messages = []
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='seleenix',
            user='root',  # récupéré depuis var d'environnement
            password=mysql_passwd  # récupéré depuis var d'environnement
        )
        cursor = connection.cursor()
        query = "SELECT * FROM channel"
        cursor.execute(query)
        # Utilisez fetchone() pour récupérer une ligne du résultat
        row = cursor.fetchone()
        while row:
            if row[1] == user_caps[socket].current_room:
                messages.append(f"{row[2]}:{row[3]}")
                #socket.send(f"old:{row[2]}:{row[3]}".encode())
            row = cursor.fetchone()
        # envoie tous les messages à l'utilisateur    
        socket.send(b'old:' + str(",".join(messages)).encode()) \
            if messages else None
    except Error as e:
        print("Erreur de connexion à la base de données", e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

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


# Cette fonction a été en partie générée par ChatGPT
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

def send_announcement(server_port):
    """
    Cette fonction permet d'envoyer dans le réseau local un message UDP
    afin d'annoncer la présence du serveur. (et ses informations)
    
    Args:
        server_port: le port du serveur
        
    Returns:
        None
        
    Raises:
        None
    
    """
    
    ip = get_ip()
    ifname =  get_interface_name_by_ip(ip)
    while connected:
        pkt = IP(src= ip, dst="255.255.255.255")\
            /UDP(sport = 9999, dport=10000)\
                /Raw(load="Server announcement:port:{}".format(server_port))
        send(pkt, iface=ifname) # cette fonction est différente de celle du tchat , c'est celle de scapy !
        time.sleep(0.5)  # Envoyer l'annonce toutes les 0.5 secondes
    return 0
# Fonction pour l'interaction avec le client
def interactive(target, host):
    """
    Fonction permettant d'initier le mode interactif avec le client.
    
    Args:
        target: le socket du client
        host: l'hôte du serveur
        
    Returns:
        None
        
    Raises:
        None
    
    """
    global connected
    global socket_list
    #connected = True
    print("Connected to client")
    restore_old_messages(target)    
    threading.Thread(target=receive, args=(target, host)).start()
    
    if len(socket_list) == 1:
        Send(target, host)
    else:
        return sys.exit() 
    sys.exit() #if not connected else None


if __name__ == "__main__":
    """
    Point d'entrée du programme serveur. (si éxécuté en tant que script)
    
    Il créé le socket du serveur et attend les connexions des clients.
    Il gère également les connexions des clients. (dans une boucle d'acceptation)
    Il gère la vérification du challenge envoyé par le client.
        
    """
    host = "0.0.0.0"
    port = arg_parse().port
    check = False
    done = False
    # Création du socket serveur
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        check = True
    except BaseException:
        print("Vérifiez que le port soit libre et l'adresse que vous avez entré soit valide")
        done = False
        
    if check:
        connected = True
        conf.verb = 0  # Pour ne pas afficher les messages de scapy
        # Afin d'annonce le serveur sur le réseau, on envoie un message UDP
        thread_load = threading.Thread(target=animate)
        thread_load.start()
        time.sleep(4)
        done = True
        
        threading.Thread(target=send_announcement, args=((port),)).start()



        # Boucle principale d'attente de connexions
        while connected:
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                conn, address = server_socket.accept()
                #print(type(conn))
                
    
                
                message = conn.recv(1024)
                message_1 = decrypt(message)
                #message_1 = message
                print(message_1)
            except ValueError as e:
                print("Le message n'a pas pu être déchiffré",e)
                conn.send("garbage".encode())
                conn.close()
            except OSError:
                pass
            else:
                if not ";" in message_1:
                    conn.send("garbage".encode())
                    conn.close()
                else:
                    #message_2 = conn.recv(1024).decode()
                    client_challenge, credentials = message_1.split(";")[0].split(","), message_1.split(";")[1].split(",")
                    connect_condition = lambda x: int(x) % 2 == 0
                    client_condition = all(connect_condition(elem) for elem in client_challenge)
                if client_condition:
                    unique_pseudo = random.choice(default_pseudo, replace=False) \
                        if credentials[0] == "default" \
                            else credentials[0]  # choisir un pseudo unique si pas de user dans credentials
                    is_auth = user_sql_handler(unique_pseudo, credentials[1], conn, str(address))
                    # ajouter au dictionnaire socket_list une entrée avec clé le pseudonyme et comme valeur le socket
                    if is_auth:
                        socket_list[f"{unique_pseudo}"] = conn
                        conn.send(f"synced,{unique_pseudo},{user_caps[conn].current_room}".encode()) if not "GUI" in message_1 \
                            else conn.send(f"synced:{unique_pseudo}:{user_caps[conn].current_room}:{user_caps[conn].allowed_room}".encode())
                        threading.Thread(target=interactive, args=(conn, host)).start()
                        #interactive(conn, host)
                        conn.close() if not connected else None
                else:
                    conn.send("garbage".encode())
                    conn.close()
        else:
            #server_socket.close()
            sys.exit()
