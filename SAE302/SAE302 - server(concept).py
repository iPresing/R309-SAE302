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
import keyboard
import time
import logging
import psutil
from math import *
logging.getLogger("scapy").setLevel(logging.CRITICAL) # pour éviter les log de warning
from scapy.all import *
import datetime
import builtins as bt




# gestion des droits utilisateurs
class user_capabilities(object):
    all_rooms = ["General","Blabla","Comptabilité", "Informatique", "Marketing"]
    current_room = "General"
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
        
class BannedUser(Exception):
    def __init__(self, message):
        super().__init__(message)
        
class LimitConnectionIP(Exception):
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
mysql_passwd = os.environ['MYSQL_PASSWD'] #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)

# Liste de pseudos par défaut
default_pseudo =  ["Nosferatu","BlackBird","Pleiades","Hyades","Undertaker","BloodyReina","Wehrwolf","LaughingFox","SnowWitch"\
    ,"Gunslinger","Sagittarius","Cyclops","Melusine","Bluebell","Verethragna","Hualien","Milan","Baldanders","Catoblepas","Banshee"\
    ,"Grimalkin","Bandersnatch","Jabberwock","Dullahan","Kirschblüte","BlackDog","Falke","Fafnir","Helianthus","Walpurgis","Griffin",\
    "Manticore","Artemis","Cato'Nine","MarchHare","Sirius","Leukosia","Gunmetalstorm","LaBete","Dendroaspis","Burnt Tayl","Gladiator",\
    "Argos","Vulture","Estoc","Grimoire","Gungnir","GaeBolg","Excalibur","Durandal","ClaiomhSolais",\
"Caladbolg","Balmung","AmeNoMurakumo"]

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

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

def user_sql_handler(user, password, socket, ip_address):
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
            if special_row:
                raise BannedUser(f"Vous avez été banni, veuillez contacter l'administrateur{str(':') + str(special_row[3]) if special_row[3] else ''}")
            else:
                pass
        
            #current_user = user_capabilities(row[0], row[3], row[2])
            user_caps[socket] = user_capabilities(row[0], row[3], row[2])
            print("Utilisateur trouvé, restauration de ses données...")
        else:
            # nouvelle requête pour vérifier occurence de l'ip si > 2 alors pass
            query = "SELECT * FROM users WHERE ip = %s OR ip = %s"
            cursor.execute(query, (ip_address,'0.0.0.0'))
            #print(ip_address)
            
            ip_row = cursor.fetchall()
            #print(ip_row)
            if len(ip_row) > 2: # 2 comptes max par ip
                raise LimitConnectionIP("Vous avez atteint la limite de connexion sur cette adresse ip")
            else:     
            
                second_query = "SELECT * FROM users WHERE username = %s"
                cursor.execute(second_query, (user,))
                if cursor.fetchone():
                    raise IncorrectPassword("Utilisateur trouvé, mais le mot de passe est incorrect")
                else:
                    print("Utilisateur non trouvé, création d'un nouvel utilisateur...")
                    cursor.execute("INSERT INTO users (username, password, allowed_room, ip) VALUES (%s, %s, %s, %s)", (user, password, str("General"), host))
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
                        socket.send(b'scb:' + str("Votre demande a été acceptée").encode())
                    else:
                        socket.send(b'scb:' + str("Votre demande a été refusée ou vous ne disposer pas des droits").encode())
                else:
                    pass
                    """
                    if row[5] == 1:
                        socket.send(f"us: Votre demande de {row[2]} a été acceptée".encode())
                    else:
                        socket.send(f"us: Votre demande de {row[2]} a été refusée".encode())"""
                
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
    #global hostup
    global connected
    global socket_list
    hostup = True
    
    while hostup:
        
        #enlever du dictionnaire socket_list les sockets [closed]
        for user_selected, socket_selected in list(socket_list.items()): # on utilise list pour éviter les erreurs de modification de taille 
            #print((user_selected, socket_selected))
            #print(bt.type(socket_selected))
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
                        # envoyer à tous les clients
                        try:
                            for user in socket_list.values():
                                user.send(msg.encode()) if msg else None
                        except OSError as err:
                            print(Fore.RED + f"Le socket {user} n'existe plus", end=f'\n{Fore.RESET}')
                            pass
                        else:
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
                    target_socket = socket_list[f"{username}"] # essaie de récupérer le socket avec le username
                except KeyError as err:
                    print(Fore.RED + f"Le pseudo {username} n'existe pas \n ou l'utilisateur n'est pas connecté", end=f'\n{Fore.RESET}')
                    pass
                else:
                    print("tacos_2")
                    target_socket.send("bye".encode())
                    username, target_socket = socket_list.popitem()
                    hostup = False
                    #target_socket.send("recon".encode())
            if "/kick" in (msg_d := msg.split(" ")):
                # A FAIRE : REMETTRE LE BLOC TRY
                time_delimiter = ["h", "m"]
                
                type = "kick"
                
                try:
                    if not msg_d[1] in socket_list.keys():
                        print(Fore.RED + f"Le pseudo {msg_d[1]} n'existe pas", end=f'\n{Fore.RESET}')
                        #raise Exception
                    elif not msg_d[2] in user_capabilities.all_rooms and msg_d[2] != "ALL":
                        print(Fore.RED + f"Le salon {msg_d[2]} n'existe pas", end=f'\n{Fore.RESET}')
                        #raise Exception
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
                                , f"{f'kick:{reasons}' if reasons else 'kick'}"\
                                    , socket_list[user] )
                            
                            # log dans query_insert
                            update_userinfo_sql(user, f"{rooms}", f"query_insert:{type}!server", socket_list[user])  
                            if rooms == 'ALL':
                                print('tacos')
                                socket_list[user].send(f'bye'.encode())
                                user, socket_list[user] = socket_list.popitem()
                                hostup = False
                                
                            elif rooms == user_caps[socket_list[user]].current_room:
                                user_caps[socket_list[user]].current_room = "General"
                                socket_list[user].send(f"jn: Succès:General".encode())
                            else:
                                socket_list[user].send(f"jn: Succès:General".encode())
                            
                                
                            """update_userinfo_sql(user, f'{rooms}!{date_debut}!{date_fin}'\
                                , f"{f'kick:{reasons}' if reasons else 'kick'}"\
                                    , socket_list[user] )"""
                                
                                
                            
                                
                            #time_k = msg_d[2].replace((keys, f",{values}") for keys, values in translate_time.items())
                            #time_k = ''.join([time_k.replace(key, f",{value}") for key, value in translate_time.items()])
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
                        hostup = False
                        
                        """update_userinfo_sql(user, None\
                                , f"{f'ban:{reasons}' if reasons else 'ban'}"\
                                    , socket_list[user] )"""
                    
                except Exception:
                    print(Fore.RED,"Le format de la commande est incorrect :\nex: /ban [pseudo] [reasons](optional)", end=f"\n{Fore.RESET}" )
            
            
            
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
                #print(user_caps[socket])
                
            if msg.startswith("/deop"):
                username = msg.split(" ")[1]
                update_userinfo_sql(username, 0, "upgrade", socket)
                #print(user_caps[socket])
                
            if msg.startswith("/users"):
                available_users = [a for a in socket_list.keys()]
                cls()
                for user in available_users:
                    print(Fore.GREEN + user + f" ({user_caps[socket_list[user]].current_room})", end=f'\n{Fore.RESET}')
                print(f'\nserver@{host} $:', end="") if msg else None
                
            if msg.startswith("/accept") or msg.startswith("/refuse"):
                if len(msg.split(" ")) > 1:
                    #user = user_caps[socket]
                    value_send = msg.split(" ")[1] + ":" + str(1 if msg.startswith("/accept") else 0)
                    update_userinfo_sql(None, value_send, "query_update", socket) # le user et socket correspondants seront récupérés suite à une requête sql
                    
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
                    #update_userinfo_sql(username, new_room, "roomdowngrade", socket)
                    #print(user_caps[socket])
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
    #global hostup
    global connected
    hostup = True
    while hostup:
        try:
            reply = socket.recv(1024).decode()
        except ConnectionResetError:
            hostup = False
            print("La connexion a été interrompue par le client")
            socket.close()
            break
        except ConnectionAbortedError:
            
            #enlever username et socket de socket_list
            socket_list[socket], socket = socket_list.popitem()
            
            hostup = False
            print("(rcv)Le serveur a fermé sa connexion")
            socket.close() if bt.type(socket) == socket else None
            break
        else:
            print("\033[2K", end="\r ")  # carriage return + clear 
            #print(reply)
            print(f"{username(socket_list,socket)}: {reply}", end="") if not "/" in reply and reply else None
            #print('\033[1F', f'\nserver@{host} $:', end="") if reply else None
            
            
            if not "/" in reply and not reply == "bye" and not reply == "/kill" and reply:
                
                # cette section servira à l'insertion des messages dans la table channel de la base de donnée
                m_username = user_caps[socket].username
                m_rooms = user_caps[socket].current_room
                id = user_caps[socket].all_rooms.index(m_rooms)
                content = reply
                
                # Cette variable contient les sockets des clients qui sont dans la même room que le client actuel
                target_list = [a if \
                    (user_caps[a].current_room == user_caps[socket].current_room)  \
                        and a != socket else None for a in socket_list.values()]
            
                for user_target in target_list:
                    try:
                        user_target.send(f"fwd:{username(socket_list,socket)}:{reply}".encode()) \
                            if user_target else None
                    except OSError as err:
                        print(Fore.RED + f"Le socket {user_target} n'existe plus", end=f'\n{Fore.RESET}')
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
                    
                    """
                    print("Une demande d'abonnement à la room", room, "a été reçue, veuillez appuyer sur entrée pour donner une réponse")
                    if (response := input(f"Voulez-vous vraiment abonner {username(socket_list,socket)} à la room {room} ? (y/n) ")) == "y":
                        update_userinfo_sql(username(socket_list,socket), room, "roomupdate", socket) \
                            if not room in user_caps[socket].allowed_room else None
                        socket.send(b'scb:' + str("Votre demande a été acceptée").encode())
                    else:
                        socket.send(b'scb:' + str("Votre demande a été refusée ou vous ne disposer pas des droits").encode())  """  
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
                            #date_fin_v2 = datetime.datetime.strptime(date_fin_v1, "%Y-%m-%d %H:%M:%S")
                            date_fin = date_fin_v1.timestamp()
                            if date_fin > time.time():
                                raise Exception(str(date_fin_v1))
                            else:
                                pass
                        else:
                            pass
                    except Exception as e:
                        #print(e)
                        socket.send(f"jn: Vous avez été kick de la room {room} time:{e}".encode())
                        #restore_old_messages(socket)
                        continue
                        
                    
                    
                    user_caps[socket].current_room = room
                    socket.send(f"jn: Succès:{room}".encode())
                    restore_old_messages(socket)
                else:
                    socket.send(f"jn: Vous ne disposez pas d'accès au salon {room}, veuillez vous y souscrire..".encode())
                    #restore_old_messages(socket)
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
            #print(f'\nserver@{host} $:', end="") if reply else None
            reply = None
    socket.close()


def restore_old_messages(socket):
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0] # récupérer l'adresse ip de l'interface
    except Exception as e:
        pass
    finally:
        s.close()
    
    return str(ip)

def get_broadcast_ip(ip):
    octets = ip.split(".")
    if 1 <= int(octets[0]) <= 126:  # Class A
        broadcast_ip = octets[0] + ".255.255.255"
    elif 128 <= int(octets[0]) <= 191:  # Class B
        broadcast_ip = octets[0] + "." + octets[1] + ".255.255"
    elif 192 <= int(octets[0]) <= 223:  # Class C
        broadcast_ip = octets[0] + "." + octets[1] + "." + octets[2] + ".255"
    else:
        raise ValueError("Adresse IP Invalide")

    return broadcast_ip
# Cette fonction a été en partie générée par ChatGPT
def get_interface_name_by_ip(ip_address):
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
    ip = get_ip()
    dst_ip_brd = get_broadcast_ip(ip)
    ifname =  get_interface_name_by_ip(ip)
    while connected:
        pkt = IP(src= ip, dst="255.255.255.255")\
            /UDP(sport = 9999, dport=10000)\
                /Raw(load="Server announcement:port:{}".format(server_port))
        #send(pkt)
        send(pkt, iface=ifname) # cette fonction est différente de celle du tchat , c'est celle de scapy !
        time.sleep(0.5)  # Envoyer l'annonce toutes les 0.5 secondes
    return 0
# Fonction pour l'interaction avec le client
def interactive(target, host):
    global connected
    global socket_list
    #connected = True
    print("Connected to client")
    restore_old_messages(target)    
    threading.Thread(target=receive, args=(target, host)).start()
    
    if len(socket_list) == 1:
        Send(target, host)
    else:
        return sys.exit(0) 
    sys.exit(0) #if not connected else None

# Création du socket serveur
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)

conf.verb = 0  # Pour ne pas afficher les messages de scapy
# Afin d'annonce le serveur sur le réseau, on envoie un message UDP
threading.Thread(target=send_announcement, args=((port),)).start()



# Boucle principale d'attente de connexions
while connected:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        conn, address = server_socket.accept()
        message = conn.recv(1024)
        message_1 = decrypt(message)
    except ValueError as e:
        print("Le message n'a pas pu être déchiffré")
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
    sys.exit(0)
