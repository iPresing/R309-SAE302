from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
import threading, socket, random, os, sys, argparse, psutil
from scapy.all import *
from subprocess import getoutput as getResults
from colorama import init, Fore, Back, Style


global connected
global room
init(autoreset=True) # pour que les couleurs s'appliquent à tout le terminal
connected = False
key = os.environ['AES_KEY'].encode() # récupérer depuis les variables d'environnements
iv = os.environ['AES_IV'].encode() #récupérer depuis les variables d'environnements
cipher = AES.new(key, AES.MODE_CBC, iv)


# variable global nommé logout_signal composée de 32 caractères aléatoires
global logout_signal
logout_signal = "".join([chr(random.randint(65, 90)) for i in range(32)])


# variable global nommée error_signal composée de 33 caractères aléatoires
global error_signal
error_signal = "".join([chr(random.randint(65, 90)) for i in range(33)])
#host = "127.0.0.1"
#port = 1234

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
        
def arg_parse():
    parser = argparse.ArgumentParser(description='Client GUI pour le chat')
    parser.add_argument('--host', type=str,
                    help='L\'ip du serveur hôte', default="127.0.0.1")
    parser.add_argument('--port', type=int,
                    help='Le port du serveur hôte', default=1234)
    parser.add_argument('--search', action='store_true',
                    help='Activer la recherche (flag)', default=False)
    return parser.parse_args()

def encrypt(payload): # pour automatiser encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(payload, AES.block_size))

def decrypt(payload): # pour automatiser decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(payload), AES.block_size).decode()


class ReceiveThread(QThread):
    messageReceived = pyqtSignal(str)
    showMessageSignal = pyqtSignal(str, str)
    showErrorMessageSignal = pyqtSignal(str, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.stopThread = False
    
    def stop(self):
        self.stopThread = True

        
    def run(self):
        while not self.stopThread:
            try:
                reply = client_socket.recv(1024).decode()
                
                if reply == 'bye':
                    raise ConnectionClosedByServer("Connection closed by server")
                
                elif reply.startswith('jn:') and 'kick' in reply:
                    
                    TimeKick = reply.split('time:')[1]
                    
                    raise KickedFromRoom(str(TimeKick))
                
                if reply:
                    self.messageReceived.emit(reply)
            except ConnectionClosedByServer:
                self.messageReceived.emit(logout_signal)
                break
            except ConnectionResetError:
                self.messageReceived.emit(logout_signal)
                #self.messageReceived.emit(f"{error_signal}: La connexion a été réinitialisée par le serveur")
                break
            except ConnectionAbortedError:
                self.messageReceived.emit(f"{error_signal}: La connexion a été interrompue par le serveur")
                break
            except KickedFromRoom as e:
                self.messageReceived.emit(f"{error_signal}: Vous avez été kick de la room jusque {str(e)}")
                pass
# application graphique PyQt6 page de connexion
class Login(QWidget):
    connected = False
    
    
    def open_chat(self):
        self.ui = ChatApp()
        connectSignals(self.ui)
        
        
    def updateNewWindowUi(self):
        global connected
        connected = self.ui.IsConnected = self.connected
        room = self.ui.room = self.current_room
        allowed_room = self.ui.allowed_room = self.allowed_room
        username = self.ui.username = self.username
        self.ui.setWindowTitle(f"Chat - {room} - {username}")
        self.ui.recvthread.start() # on lance le thread de réception des messages     
        self.ui.message_list.addItem(f"Vous êtes connecté à la room {room}")
        
        if "General" in allowed_room:
            self.ui.general_room.setStyleSheet("background-color: lightgreen;")
        else:
            self.ui.general_room.setStyleSheet("background-color: red;")
            
        if "Blabla" in allowed_room:
            self.ui.blabla_room.setStyleSheet("background-color: lightgreen;")
        else:
            self.ui.blabla_room.setStyleSheet("background-color: red;")
            
        if "Comptabilité" in allowed_room:
            self.ui.compta_room.setStyleSheet("background-color: lightgreen;")
        else:
            self.ui.compta_room.setStyleSheet("background-color: red;")
            
        if "Informatique" in allowed_room:
            self.ui.info_room.setStyleSheet("background-color: lightgreen;")
        else:
            self.ui.info_room.setStyleSheet("background-color: red;")
            
        if "Marketing" in allowed_room:
            self.ui.market_room.setStyleSheet("background-color: lightgreen;")
        else:
            self.ui.market_room.setStyleSheet("background-color: red;")
        
    def __init__(self):
        super().__init__()
        #client_socket_create()
        self.setWindowTitle("Login")
        #self.resize(1000, 1000)
        #self.setGeometry(100, 100, 600, 400)
        self.layout = QGridLayout()
        self.setLayout(self.layout)
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.show_password = QCheckBox("Show password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password.setChecked(False)
        self.login_button = QPushButton("Login")
        self.show_password.stateChanged.connect(lambda: self.password.setEchoMode(QLineEdit.EchoMode.Normal) if self.show_password.isChecked() else self.password.setEchoMode(QLineEdit.EchoMode.Password))
        self.layout.addWidget(QLabel("Username: "), 0, 0)
        self.layout.addWidget(self.username, 0, 1)
        self.layout.addWidget(QLabel("Password: "), 1, 0)
        self.layout.addWidget(self.password, 1, 1)
        self.layout.addWidget(self.show_password, 2, 1)
        self.layout.addWidget(self.login_button, 3, 0, 1, 2)
        
        
        #self.layout.addWidget(self.register_button, 2, 1)
        self.login_button.clicked.connect(self.login)
        #self.register_button.clicked.connect(self.register)
        self.show()
    def login(self):
        client_socket_create()
        username = self.username.text() or "default"
        password = self.password.text()
        if not password:
            QMessageBox.critical(self, "Error", "Veuillez entrer un mot de passe")
            return 0
        challenge = ",".join([str(random.randint(1,65535) * 2) for i in range(16)]) # un challenge pour reconnaître une connexion autorisée
        
        payload = (challenge + ";" + username + "," + password + ";" + "GUI").encode()
    
     
        
        try:               
            client_socket.connect((host, port))
            client_socket.send(encrypt(payload))
            synced = client_socket.recv(1024).decode() # on attend la réponse du serveur pour continuer
            print(synced)
            #if not "synced" in synced:
           
            if "banni" in synced:
                raise BannedFromServer(synced)
            elif not synced.startswith("synced"):
                raise ChallengeRefused("Challenge refused")
                #connected = True
                #widgets.setCurrentIndex(widgets.currentIndex() + 1)
            
        except BannedFromServer as e:
            QMessageBox.critical(self, "Error", f"{str(e)}")
            pass
        except ChallengeRefused as err:
            QMessageBox.critical(self, "Error", "Vous n'êtes pas autorisé à accéder à ce serveur...")
            pass
        except ConnectionRefusedError as err:
            QMessageBox.critical(self, "Error", "La connexion n'a pas aboutie, vérifiez que le serveur est bien lancé et que l'adresse est correcte")
            pass
            #print(Fore.RED + " \nLa connexion n'a pas aboutie, vérifiez que le serveur est bien lancé et que l'adresse est correcte")
        except OSError as err:
            client_socket.close()
            
        
        
        else:
            self.connected = True
            self.username = synced.split(':')[1]
            self.current_room = synced.split(':')[2].lstrip()
            self.allowed_room = synced.split(':')[3].lstrip()
            
            self.open_chat()
            self.updateNewWindowUi()
        
        
        return self.close()


# application graphique PyQt6 page de tchat
# menu latéral gauche avec 5 boutons
# Text box contenant le message à envoyer
# bouton envoyer

class ChatApp(QWidget):
    connected = False
    allowed_room = None
    room = None
    username = None
    last_message = None
    
    # Add signals
    showMessageSignal = pyqtSignal(str, str)
    showErrorMessageSignal = pyqtSignal(str, str)
    stopThreadSignal = pyqtSignal()
    def __init__(self):
            super().__init__()
            self.setWindowTitle('Chat App')

            # Créer des widgets
            self.message_list = QListWidget()
            self.message_input = QLineEdit()
            self.send_button = QPushButton('Envoyer')
            self.quit_button = QPushButton('Quitter')
            self.general_room = QPushButton("General" )
            self.blabla_room = QPushButton("Blabla")
            self.compta_room = QPushButton("Comptabilité")
            self.info_room = QPushButton("Informatique")
            self.market_room = QPushButton("Marketing")
            

            # Mettre en place la mise en page
            upper_layout = QHBoxLayout()
            layout = QVBoxLayout()
            h_layout = QHBoxLayout()
            side_menu_layout = QVBoxLayout()

            
            #menu latéral gauche avec 5 boutons
            side_menu_layout.addWidget(self.general_room)
            side_menu_layout.addWidget(self.blabla_room)
            side_menu_layout.addWidget(self.compta_room)
            side_menu_layout.addWidget(self.info_room)
            side_menu_layout.addWidget(self.market_room)
            
            
            # menu latéral + message list 
            upper_layout.addLayout(side_menu_layout)
            upper_layout.addWidget(self.message_list)

            layout.addLayout(upper_layout)

            h_layout.addWidget(self.message_input)
            h_layout.addWidget(self.send_button)
            h_layout.addWidget(self.quit_button)

            #h_layout.addLayout(side_menu_layout)
            layout.addLayout(h_layout)
            

            self.setLayout(layout)

            # Connecter le signal du bouton "Envoyer" à la fonction correspondante
            self.send_button.clicked.connect(self.sendMessage)
            
            # Connecter le signal du bouton "Quitter" à la fonction correspondante
            self.quit_button.clicked.connect(self.close)
            
            self.blabla_room.clicked.connect(lambda: self.join(self.blabla_room))
            self.general_room.clicked.connect(lambda: self.join(self.general_room))
            self.compta_room.clicked.connect(lambda: self.join(self.compta_room))
            self.info_room.clicked.connect(lambda: self.join(self.info_room))
            self.market_room.clicked.connect(lambda: self.join(self.market_room))
            
            #self.recvthread = threading.Thread(target=self.receiveMessage)
            #self.recvthread = ReceiveThread(self)
            #connectSignals(self)
            
            self.recvthread = ReceiveThread(self)
            self.recvthread.messageReceived.connect(self.handleReceivedMessage)
            connectSignals(self)
            

            
            

            # Définir la géométrie de la fenêtre principale
            #self.setGeometry(100, 100, 600, 400)
            self.setGeometry(100, 100, 600, 400)

            self.show()
            
    def showInfoMessage(self, title, message):
        self.showMessageSignal.emit(title, message)

    def showCriticalMessage(self, title, message):
        self.showErrorMessageSignal.emit(title, message)
        
    # afin d'impacter toutes les instances de ChatApp en set
    def EditConnected(self, new_value):
        ChatApp.connected = new_value
    # afin d'impacter toutes les instances de ChatApp en get
    def IsConnected(self):
        return ChatApp.connected 
        
            
    def join(self, button_room):
        if button_room.styleSheet() == "background-color: lightgreen;":
            room = button_room.text()
            client_socket.send(f"/join {room}".encode())
        else:
            room = button_room.text()
            client_socket.send(f"/subscribe {room}".encode())
        client_socket.send("/rooms".encode()) # pour rafraîchir           
        
    def close(self):
        self.EditConnected = False
        #global connected
        #connected = False
        #self.connected = False
        #ouvrir une nouvelle instance de Login
        login = Login()
        login.setWindowTitle("Login")
        login.show()
        return super().close()
    
    def closeEvent(self, event):
        self.recvthread.stop()
        client_socket.close()
        event.accept()
        
    def sendMessage(self):

        if self.IsConnected:
            # Récupérer le texte de la boîte de texte
            message_text = self.message_input.text()
            self.last_message = message_text
            try:
                # Envoyer le texte
                client_socket.send(message_text.encode()) if message_text else None
                self.message_list.addItem(f"Vous: {message_text}") if message_text else None
                if message_text == "bye" or message_text == "arret":
                    raise ConnectionAbortedError("Closed connection")
                self.message_input.clear()
            except ConnectionAbortedError as err:
                if not message_text == "bye":
                    QMessageBox.critical(self, "Error", "La connexion a été interrompue par le serveur")
                    #self.connected = False
                    #client_socket.close()
                    self.close()
                else:
                    QMessageBox.information(self, "Info", "Vous avez bien été déconnecté du serveur")
                    #self.connected = False
                    #client_socket.close()
                    self.close()
        else:
            pass
        return 0
    
    def restore_old_messages(self, payload):
        all_messages = payload.split("old:")[1].split(",")
        
        # restaure les messages du salon actuel
        for message in all_messages:
            self.message_list.addItem(f"{message.split(':')[0]}: {message.split(':')[1]}" \
                if message.split(':')[0] != self.username \
                    else f"Vous: {message.split(':')[1]}")
            
                    
        return 0
    
    
    def handleReceivedMessage(self, message):
        print(error_signal, logout_signal)
        
        if message.startswith(error_signal):
            QMessageBox.critical(self, "Error", message[len(f"{error_signal}:"):])
            #self.close()
        elif message == logout_signal:
            QMessageBox.information(self, "Déconnexion", "Vous avez bien été déconnecté du serveur")
            self.close()
            #self.showMessageSignal.emit("Déconnexion", "Vous avez bien été déconnecté du serveur")
        elif message.startswith("cmd:"):
            message = message.split("cmd:")[1].split(',')
            
            for room in message:
                if "General" in room:
                    self.general_room.setStyleSheet("background-color: {color};"\
                        .format(color="lightgreen" if room.startswith("alw:") else "red"))
                elif "Blabla" in room:
                    self.blabla_room.setStyleSheet("background-color: {color};"\
                        .format(color="lightgreen" if room.startswith("alw:") else "red"))
                elif "Comptabilité" in room:
                    self.compta_room.setStyleSheet("background-color: {color};"\
                        .format(color="lightgreen" if room.startswith("alw:") else "red"))
                elif "Informatique" in room:
                    self.info_room.setStyleSheet("background-color: {color};"\
                        .format(color="lightgreen" if room.startswith("alw:") else "red"))
                elif "Marketing" in room:
                    self.market_room.setStyleSheet("background-color: {color};"\
                        .format(color="lightgreen" if room.startswith("alw:") else "red"))
                else:
                    pass
            """
            if "alw:" in message:
                for a in message.split(","):
                    if "alw:" in a:
                        room = a.split("alw:")[1]
                    if room == "General":
                        self.general_room.setStyleSheet("background-color: lightgreen;")
                    elif room == "Blabla":
                        self.blabla_room.setStyleSheet("background-color: lightgreen;")
                    elif room == "Comptabilité":
                        self.compta_room.setStyleSheet("background-color: lightgreen;")
                    elif room == "Informatique":
                        self.info_room.setStyleSheet("background-color: lightgreen;")
                    elif room == "Marketing":
                        self.market_room.setStyleSheet("background-color: lightgreen;")
                    else:
                        pass
            """
            message = None
        
        elif message.startswith("scb:"): # le serveur renvoie la réponse du /subscribe
            message = message.split("scb:")[1]
            
            if "accept" in message:
                #QMessageBox.information(self, "Info", "Vous pouvez accéder à la room")
                #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous pouvez accéder à la room"))
                client_socket.send("/rooms".encode())
            else:
                client_socket.send("/rooms".encode())
                #QMessageBox.critical(self, "Error", "Vous ne pouvez pas accéder à la room")
                #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous ne pouvez pas accéder à la room"))
            message = None
            
        elif message.startswith("users:"): # le serveur renvoie la liste des utilisateurs
            pass # à faire plus tard
        
        elif message.startswith("jn:"): # le serveur renvoie la réponse du /join
            message = message.split("jn:")[1]
            if "Succès" in message:
                self.room = message.split(":")[1]
                self.message_list.clear()
                self.message_list.addItem(f"Vous avez rejoint la room {self.room}")
                #QMessageBox.information(self, "Info", "Vous avez bien rejoint la room")
                #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous avez bien rejoint la room"))
            else:
                room = message.split(",")[0].split(" ")[-1]          
                if room == "General":
                    self.general_room.setStyleSheet("background-color: red;")
                elif room == "Blabla":
                    self.blabla_room.setStyleSheet("background-color: red;")
                elif room == "Comptabilité":
                    self.compta_room.setStyleSheet("background-color: red;")
                elif room == "Informatique":
                    self.info_room.setStyleSheet("background-color: red;")
                elif room == "Marketing":
                    self.market_room.setStyleSheet("background-color: red;")
                else:
                    pass
                
                self.room = room
                self.message_list.clear()
                self.message_list.addItem(f"Vous avez rejoint la room {self.room}")
                
                #QMessageBox.critical(self, "Error", "Vous n'avez pas pu rejoindre la room")
                #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous n'avez pas pu rejoindre la room"))
            message = None
            
        elif message.startswith("us:"): # le serveur renvoie la réponse du /unsubscribe
            message = message.split("us:")[1]
            if "désabonné" in message:
                #client_socket.send("/rooms".encode())
                self.join(self.general_room)
                #QMessageBox.information(self, "Info", "Vous avez bien quitté la room")
                #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous avez bien quitté la room"))
            else:
                pass
                #QMessageBox.critical(self, "Error", "Vous n'avez pas pu quitter la room")
                #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous n'avez pas pu quitter la room"))
            message = None
            
        elif message.startswith("fwd:"): # le serveur renvoie la réponse du /forward
            fwd_user, fwd_message = message.split("fwd:")[1].split(":")[0], message.split("fwd:")[1].split(":")[1]
            self.message_list.addItem(f"{fwd_user}: {fwd_message}")
            message = None
            
        elif message.startswith("old:"): # le serveur renvoie les anciens messages
            self.restore_old_messages(message)
            message = None
        
        """
        if message == "bye" or message == "arret":
            self.EditConnected = False
            client_socket.close()
            raise ConnectionClosedByServer("Closed connection")
        """
        if message:
            self.message_list.addItem(f"server:{message}")
            message = None
            
        return 0
        
        
        
        
        
        
        
    """
    def receiveMessage(self):
        while self.IsConnected: # récupère variable globale
            
            if self.stopThreadSignal.emit():
                break
            try:
                reply = client_socket.recv(1024).decode()
                
                
                if "cmd:" in reply:
                    reply = reply.split("cmd:")[1]
                    if "alw:" in reply:
                        for a in reply.split(","):
                            if "alw:" in a:
                                room = a.split("alw:")[1]
                            if room == "General":
                                self.general_room.setStyleSheet("background-color: lightgreen;")
                            elif room == "Blabla":
                                self.blabla_room.setStyleSheet("background-color: lightgreen;")
                            elif room == "Comptabilité":
                                self.compta_room.setStyleSheet("background-color: lightgreen;")
                            elif room == "Informatique":
                                self.info_room.setStyleSheet("background-color: lightgreen;")
                            elif room == "Marketing":
                                self.market_room.setStyleSheet("background-color: lightgreen;")
                            else:
                                pass
                    reply = None
                    
                elif "scb:" in reply: # le serveur renvoie la réponse du /subscribe
                    reply = reply.split("scb:")[1]
                    
                    if "accept" in reply:
                        #QMessageBox.information(self, "Info", "Vous pouvez accéder à la room")
                        #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous pouvez accéder à la room"))
                        client_socket.send("/rooms".encode())
                    else:
                        client_socket.send("/rooms".encode())
                        #QMessageBox.critical(self, "Error", "Vous ne pouvez pas accéder à la room")
                        #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous ne pouvez pas accéder à la room"))
                    reply = None
                    
                elif "users:" in reply: # le serveur renvoie la liste des utilisateurs
                    pass # à faire plus tard
                
                elif "jn:" in reply: # le serveur renvoie la réponse du /join
                    reply = reply.split("jn:")[1]
                    if "Succès" in reply:
                        self.room = reply.split(":")[1]
                        self.message_list.clear()
                        self.message_list.addItem(f"Vous avez rejoint la room {self.room}")
                        #QMessageBox.information(self, "Info", "Vous avez bien rejoint la room")
                        #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous avez bien rejoint la room"))
                    else:
                        room = reply.split(",")[0].split(" ")[-1]          
                        if room == "General":
                            self.general_room.setStyleSheet("background-color: red;")
                        elif room == "Blabla":
                            self.blabla_room.setStyleSheet("background-color: red;")
                        elif room == "Comptabilité":
                            self.compta_room.setStyleSheet("background-color: red;")
                        elif room == "Informatique":
                            self.info_room.setStyleSheet("background-color: red;")
                        elif room == "Marketing":
                            self.market_room.setStyleSheet("background-color: red;")
                        else:
                            pass
                    
                        self.room = room
                        self.message_list.clear()
                        self.message_list.addItem(f"Vous avez rejoint la room {self.room}")
                        
                        #QMessageBox.critical(self, "Error", "Vous n'avez pas pu rejoindre la room")
                        #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous n'avez pas pu rejoindre la room"))
                    reply = None
                    
                elif "us:" in reply: # le serveur renvoie la réponse du /unsubscribe
                    reply = reply.split("us:")[1]
                    if "désabonné" in reply:
                        self.join(self.general_room)
                        client_socket.send("/rooms".encode())
                        #QMessageBox.information(self, "Info", "Vous avez bien quitté la room")
                        #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Info"), Q_ARG(str, "Vous avez bien quitté la room"))
                    else:
                        pass
                        #QMessageBox.critical(self, "Error", "Vous n'avez pas pu quitter la room")
                        #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "Vous n'avez pas pu quitter la room"))
                    reply = None
                    
                elif "fwd:" in reply: # le serveur renvoie la réponse du /forward
                    fwd_user, fwd_reply = reply.split("fwd:")[1].split(":")[0], reply.split("fwd:")[1].split(":")[1]
                    self.message_list.addItem(f"{fwd_user}: {fwd_reply}")
                    reply = None
                    
                elif "old:" in reply: # le serveur renvoie les anciens messages
                    self.restore_old_messages(reply)
                    reply = None
                
                if reply == "bye" or reply == "arret":
                    self.EditConnected = False
                    client_socket.close()
                    raise ConnectionClosedByServer("Closed connection")
                
                if reply:
                    self.message_list.addItem(f"server:{reply}")
                    reply = None
                
            except ConnectionClosedByServer as err:
                print("La connexion a été fermée par le serveur")
                #QMessageBox.information(self, "Déconnexion", "Vous avez bien été déconnecté du serveur") if not self.last_message == "bye" else None
                #QMetaObject.invokeMethod(self, "showInfoMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Déconnexion"), Q_ARG(str, "Vous avez bien été déconnecté du serveur")) if not self.last_message == "bye" else None
                #client_socket.close()
                #self.connected = False
                #connected = False
                self.EditConnected = False
                
            except ConnectionResetError as err:
                print("La connexion a été réinitialisée par le serveur")
                #QMessageBox.critical(self, "Error", "La connexion a été réinitialisée par le serveur") if not self.last_message == "bye" else None
                #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "La connexion a été réinitialisée par le serveur")) if not self.last_message == "bye" else None
                #client_socket.close()
                #self.connected = False
                #connected = False
                self.EditConnected = False
                
            except ConnectionAbortedError as err:
                
                #QMessageBox.critical(self, "Error", "La connexion a été interrompue par le serveur") if not self.last_message == "bye" else None
                #QMetaObject.invokeMethod(self, "showCriticalMessage", Qt.ConnectionType.QueuedConnection, Q_ARG(str, "Error"), Q_ARG(str, "La connexion a été interrompue par le serveur")) if not self.last_message == "bye" else None
                #client_socket.close()

                #self.connected = False
                #connected = False
                self.EditConnected = False
            
            else:
                pass


        return self.close()
"""        
    
def connectSignals(chat_app_instance):
    chat_app_instance.showMessageSignal.connect(chat_app_instance.showInfoMessage)
    chat_app_instance.showErrorMessageSignal.connect(chat_app_instance.showCriticalMessage)
def client_socket_create():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
    return 0

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
def handle_announcement(pkt):
    global port, host
    if pkt.haslayer(IP) and pkt.haslayer(UDP):
        load = pkt[Raw].load.decode('utf-8')
        if "Server announcement" in load:
            print("Received announcement:", load)
            server_ip = pkt[IP].src
            #server_port = pkt[UDP].sport - 1
            server_port = load.split(":")[2]
            print("Server IP:", server_ip)
            print("Server Port:", server_port)
            port = int(server_port)
            host = server_ip
            

if __name__ == "__main__":
    args = arg_parse()
    
    if args.search:
        vm_check = True if "virtualbox" in getResults('WMIC COMPUTERSYSTEM GET MODEL').lower() else False
        #vm_check = False
        if not vm_check:
            c_iface = get_interface_name_by_ip(get_ip())
            print("searching for server...")
            client_ports = 9999
            filters = f"udp port {client_ports}"
            sniff(prn=handle_announcement, filter=filters, store=0, iface=c_iface, timeout=20, count=1)
        else:
            print(Fore.RED + "Vous ne pouvez pas lancer le client en mode recherche depuis une machine virtuelle." + Fore.YELLOW + "\nIl est important de noter que vous devriez mettre le serveur sur cette VM et les clients sur des machines physiques.(pour que ça puisse fonctionner)")
            sys.exit()
    else:
        host = args.host
        port = args.port
    #client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    app = QApplication(sys.argv)
    widgets = QStackedWidget()
    login = Login()
    login.setWindowTitle("Login")
    app.exec()
