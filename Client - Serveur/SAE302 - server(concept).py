import socket
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


# gestion des droits utilisateurs
class user_capabilities(object):
    all_rooms = ["General","Blabla","Comptabilité", "Informatique", "Marketing"]
    def __init__(self, username, allowed_room, is_admin):
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
        
    
        
    def is_admin(self):
        return True if self.is_admin else False

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
        
        
# Configuration du serveur
host = "0.0.0.0"
port = 1234
global connected
global socket_list
global user_caps
connected = True
socket_list = {} # dictionnaire contenant les sockets des clients
user_caps = {} # dictionnaire contenant les droits des utilisateurs
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

def encrypt(payload): # pour automatiser encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))

def decrypt(payload): # pour automatiser decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(payload), AES.block_size).decode()

def user_sql_handler(user, password, socket):
    global current_user
    password_salt = encrypt(password.encode()) + encrypt(user.encode())
    password = hashlib.sha256(password_salt).hexdigest()
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='seleenix',
            user='root',  # récupéré depuis var d'environnement
            password='toto'  # récupéré depuis var d'environnement
        )
        cursor = connection.cursor()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (user, password))

        # Utilisez fetchone() pour récupérer une ligne du résultat
        row = cursor.fetchone()

        if row:
            print(row)
            #current_user = user_capabilities(row[0], row[3], row[2])
            user_caps[socket] = user_capabilities(row[0], row[3], row[2])
            print("Utilisateur trouvé, restauration de ses données...")
        else:
            second_query = "SELECT * FROM users WHERE username = %s"
            cursor.execute(second_query, (user,))
            if cursor.fetchone():
                raise IncorrectPassword("Utilisateur trouvé, mais le mot de passe est incorrect")
            else:
                print("Utilisateur non trouvé, création d'un nouvel utilisateur...")
                cursor.execute("INSERT INTO users (username, password, allowed_room) VALUES (%s, %s, %s)", (user, password, str("General")))
                connection.commit()
        return True
    except Error as e:
        print("Erreur de connexion à la base de données", e)
    except IncorrectPassword as e:
        print(e)
        socket.close()
        return False
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            
def update_userinfo_sql(user, value, reason, socket):
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='seleenix',
            user='root',  # récupéré depuis var d'environnement (pas si sensible)
            password='toto'  # récupéré depuis var d'environnement (exemple de mot de passe)
        )
        cursor = connection.cursor()
        if reason == "upgrade":
            query = "UPDATE users SET is_admin = %s WHERE username = %s"
            cursor.execute(query, (value, user))
            user_caps[socket].is_admin = value
            connection.commit()
        elif reason == "roomupdate":
            query = "UPDATE users SET allowed_room = %s WHERE username = %s"
            cursor.execute(query, (value, user))
            user_caps[socket].allowed_room = value
            connection.commit()
        elif reason == "password":
            query = "UPDATE users SET password = %s WHERE username = %s"
            cursor.execute(query, (value, user))
            connection.commit()
        else:
            raise Exception("La raison n'est pas valide (upgrade, roomupdate, password)")
    except Exception as e:
        print(e)
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()    
            
            
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
                condition = ["/deop" in msg,"/op" in msg, msg == "bye"]
                if any(condition):
                    pass
                else:
                    socket.send(msg.encode()) if msg else None
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
            if "/op" in msg:
                username = msg.split(" ")[1]
                update_userinfo_sql(username, 1, "upgrade", socket)
                #print(user_caps[socket])
                
            if "/deop" in msg:
                username = msg.split(" ")[1]
                update_userinfo_sql(username, 0, "upgrade", socket)
                #print(user_caps[socket])
                
                
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
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)

# Boucle principale d'attente de connexions
while connected:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    conn, address = server_socket.accept()
    message = conn.recv(1024)
    message_1 = decrypt(message)
    if not ";" in message_1:
        conn.send("garbage".encode())
        conn.close()
    else:
        #message_2 = conn.recv(1024).decode()
        client_challenge = message_1.split(";")[0].split(",")
        credentials = message_1.split(";")[1].split(",")
        connect_condition = lambda x: int(x) % 2 == 0
        client_condition = all(connect_condition(elem) for elem in client_challenge)
    if client_condition:
        unique_pseudo = random.choice(default_pseudo, replace=False) \
            if credentials[0] == "default" \
                else credentials[0]  # choisir un pseudo unique si pas de user dans credentials
        is_auth = user_sql_handler(credentials[0], credentials[1], conn)
        # ajouter au dictionnaire socket_list une entrée avec clé le pseudonyme et comme valeur le socket
        if is_auth:
            socket_list[f"{unique_pseudo}"] = conn
            conn.send(f"synced,{unique_pseudo}".encode())
            threading.Thread(target=interactive, args=(conn, host)).start()
            conn.close() if not connected else None
    else:
        conn.send("garbage".encode())
        conn.close()
