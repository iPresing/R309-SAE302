"""
Cet extrait de code est la version graphique du client qui se connecte à un serveur à l'aide d'une connexion socket.

Exemple d'utilisation :
python gui.py --host 127.0.0.1 --port 1234

Entrées :
- host : l'adresse IP du serveur
- port : le port du serveur
- search : activer la recherche de serveur

Sorties:
- GUI : une interface graphique pour le chat
"""
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
init(autoreset=True) # Pour réinitialiser les couleurs à chaque nouvel affichage 
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
    """
    Fonction permettant de récupérer les arguments de la ligne de commande.
    Mais aussi d'ajouter des explicatifs sur les arguments.
    
    Args:
        None
        
    Returns:
        args (obj): Les arguments de la ligne de commande.
    """
    parser = argparse.ArgumentParser(description='Client GUI pour le chat')
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


class ReceiveThread(QThread):
    """
    Classe permettant de recevoir les messages du serveur.
    Elle fonctionne via les envois de signaux.
    
    Args:
        QThread (obj): La classe parente.
    
    Attributes:
        messageReceived (obj): Un signal pour recevoir les messages.
        showMessageSignal (obj): Un signal pour afficher les messages.
        showErrorMessageSignal (obj): Un signal pour afficher les messages d'erreur.
        stopThread (bool): Un booléen pour arrêter le thread.
        
    Methods:
        stop (func): Arrêter le thread.
        run (func): Lancer le thread.
    
    """
    messageReceived = pyqtSignal(str)
    showMessageSignal = pyqtSignal(str, str)
    showErrorMessageSignal = pyqtSignal(str, str)
    
    def __init__(self, parent=None):
        """
        Constructeur de la classe ReceiveThread.
        
        Classe permettant de recevoir les messages du serveur.
        Elle fonctionne via les envois de signaux.
    
        Args:
            QThread (obj): La classe parente.
        
        Attributes:
            messageReceived (obj): Un signal pour recevoir les messages.
            showMessageSignal (obj): Un signal pour afficher les messages.
            showErrorMessageSignal (obj): Un signal pour afficher les messages d'erreur.
            stopThread (bool): Un booléen pour arrêter le thread.
            
        Methods:
            stop (func): Arrêter le thread.
            run (func): Lancer le thread.
        """
        super().__init__(parent)
        self.stopThread = False
    
    def stop(self):
        """
        Fonction permettant d'arrêter le thread.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            None
        """
        self.stopThread = True

        
    def run(self):
        """
        Fonction permettant de lancer le thread.
        
        Args:
            None
            
        Returns:
            None (envoie des signaux)
            
        Raises:
            None
        """
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
    """
    Classe correspondant à la fenêtre de connexion.
    
    Args:
        QWidget (obj): La classe parente.
        
    Attributes:
        username (str): Le nom d'utilisateur.
        password (str): Le mot de passe.
        show_password (obj): Un bouton pour afficher le mot de passe.
        login_button (obj): Un bouton pour se connecter.
        register_button (obj): Un bouton pour s'inscrire. [non utilisé]
        layout (obj): Le layout de la fenêtre.
        ui (obj): L'instance de la classe ChatApp.
        connected (bool): Un booléen pour savoir si l'utilisateur est connecté.
        current_room (str): La room actuelle.
        allowed_room (str): Les rooms autorisées.
    
    Methods:
        open_chat (func): Ouvrir la fenêtre de chat.
        updateNewWindowUi (func): Mettre à jour l'interface de la fenêtre de chat.
        login (func): Se connecter.
        register (func): S'inscrire. [non utilisé]
    
    """
    connected = False
    
    
    def open_chat(self):
        """
        Fonction permettant d'ouvrir la fenêtre de chat.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            None
        
        """
        self.ui = ChatApp()
        connectSignals(self.ui)
        
        
    def updateNewWindowUi(self):
        """
        Fonction permettant de mettre à jour l'interface de la fenêtre de chat.
        
        Args:
            None
        
        Returns:
            None
            
        Raises:
            None
        
        """
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
        """
        Constructeur de la classe Login.
        
        Classe correspondant à la fenêtre de connexion.
    
        Args:
            QWidget (obj): La classe parente.
            
        Attributes:
            username (str): Le nom d'utilisateur.
            password (str): Le mot de passe.
            show_password (obj): Un bouton pour afficher le mot de passe.
            login_button (obj): Un bouton pour se connecter.
            register_button (obj): Un bouton pour s'inscrire. [non utilisé]
            layout (obj): Le layout de la fenêtre.
            ui (obj): L'instance de la classe ChatApp.
            connected (bool): Un booléen pour savoir si l'utilisateur est connecté.
            current_room (str): La room actuelle.
            allowed_room (str): Les rooms autorisées.
        
        Methods:
            open_chat (func): Ouvrir la fenêtre de chat.
            updateNewWindowUi (func): Mettre à jour l'interface de la fenêtre de chat.
            login (func): Se connecter.
            register (func): S'inscrire. [non utilisé]
        
        """
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
        """
        Fonction permettant de se connecter.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            BannedFromServer: Si l'utilisateur est banni du serveur.
            ChallengeRefused: Si le challenge est refusé.
            ConnectionRefusedError: Si la connexion est refusée.
        
        """
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

class AdminPanel(QWidget):
    """
    Panneau constamment ouvert et affiché à l'écran pour les administrateurs.
    Ceux-ci peuvent accepter ou refuser les demandes d'accès à une room.
    Et aussi récupérer les requêtes actuelles avec le bouton "Refresh".
    
    (Il est important de noter que les utilisateurs basiques n'auront aucune réponse)
    
    Args:
        QWidget (obj): La classe parente.
        
    Attributes:
        dropdown_list (obj): La liste déroulante.
    
    Methods:
        accept_action (func): Accepter une requête.
        refuse_action (func): Refuser une requête.
        refresh_action (func): Rafraîchir les requêtes.
        updateUI (func): Mettre à jour l'interface.
        
    """
    def __init__(self):
        """
        Constructeur de la classe AdminPanel.
        
        Panneau constamment ouvert et affiché à l'écran pour les administrateurs.
        Ceux-ci peuvent accepter ou refuser les demandes d'accès à une room.
        Et aussi récupérer les requêtes actuelles avec le bouton "Refresh".
        
        (Il est important de noter que les utilisateurs basiques n'auront aucune réponse)
        
        Args:
            QWidget (obj): La classe parente.
            
        Attributes:
            dropdown_list (obj): La liste déroulante.
        
        Methods:
            accept_action (func): Accepter une requête.
            refuse_action (func): Refuser une requête.
            refresh_action (func): Rafraîchir les requêtes.
            updateUI (func): Mettre à jour l'interface.
        """
        super().__init__()

        
        admin_layout = QVBoxLayout()

        
        admin_layout.addWidget(QLabel("Admin Panel"))

        
        self.dropdown_list = QComboBox()
        
        self.setFixedSize(457, 167)
        
        admin_layout.addWidget(self.dropdown_list)

        
        accept_button = QPushButton("Accept")
        refuse_button = QPushButton("Refuse")
        refresh_button = QPushButton("Refresh")
        accept_button.clicked.connect(self.accept_action)
        refuse_button.clicked.connect(self.refuse_action)
        refresh_button.clicked.connect(self.refresh_action)

        
        admin_layout.addWidget(accept_button)
        admin_layout.addWidget(refuse_button)
        admin_layout.addWidget(refresh_button)

        self.setLayout(admin_layout)

    def accept_action(self):
        """
        Fonction permettant d'accepter une requête.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            None
        """
        selected_option = self.dropdown_list.currentText()
        print(f"Accepted: {selected_option}")
        
        client_socket.send(f"/accept:{login.username}:{selected_option.split(' ')[1]}".encode()) if selected_option else None
        #client_socket.send(f"/accept:{selected_option.split(' ')[1]}".encode()) if selected_option else None
        #enlever la requête de la liste déroulante
        self.dropdown_list.removeItem(self.dropdown_list.currentIndex()) if selected_option else None

    def refuse_action(self):
        """
        Fonction permettant de refuser une requête.
        
        Args:
            None
        
        Returns:
            None
            
        Raises:
            None
            
        """
        selected_option = self.dropdown_list.currentText()
        print(f"Refused: {selected_option}")
        
        client_socket.send(f"/refuse:{login.username}:{selected_option.split(' ')[1]}".encode()) if selected_option else None
        #client_socket.send(f"/refuse:{selected_option.split(' ')[1]}".encode()) if selected_option else None
        #enlever la requête de la liste déroulante
        self.dropdown_list.removeItem(self.dropdown_list.currentIndex()) if selected_option else None
        
        
    def refresh_action(self):
        """
        Fonction permettant de rafraîchir les requêtes.
        En réalité, elle permet surtout de les récupérer.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            None
        
        """
        client_socket.send(f"/query:{login.username}".encode())
        
        
        
    # mettre à jour l'ui suite à un ajout externe d'éléments dans la liste déroulante
    def updateUI(self, payload):
        """
        Fonction permettant de mettre à jour l'interface.
        Et d'ajouter dans la liste déroulante les requêtes.
        
        Args:
            payload (str): Le payload à traiter.
            
        Returns:
            None
            
        Raises:
            None
        
        
        """
        query = payload.split("query:")[1].replace("\'", "").split("!")    
        for q in query:
            q = q.replace("[", "").replace("]", "").split(",") # pour changer le string avec les "[]" en vrai liste
            
            try:
                if int(q[-1]) == 0:
                    # ajouter à la liste déroulante si élément pas déjà présent
                    self.dropdown_list.addItem(f"ID: {q[0]} -> {q[1]} {q[2]} {q[3]}") \
                        if not f"ID: {q[0]} -> {q[1]} {q[2]} {q[3]}" in [self.dropdown_list.itemText(i) \
                            for i in range(self.dropdown_list.count())] else None
            except ValueError:
                pass
            
        return 0
        
# application graphique PyQt6 page de tchat
# menu latéral gauche avec 5 boutons
# Text box contenant le message à envoyer
# bouton envoyer

class ChatApp(QWidget):
    """
    Classe réprésentant la fenêtre graphique du chat.
    
    Args:
        QWidget (obj): La classe parente.
        
    Attributes:
        connected (bool): Un booléen pour savoir si l'utilisateur est connecté.
        allowed_room (str): Les rooms autorisées.
        room (str): La room actuelle.
        username (str): Le nom d'utilisateur.
        last_message (str): Le dernier message envoyé.
        showMessageSignal (str, str): Un signal pour afficher les messages.
        showErrorMessageSignal (str, str): Un signal pour afficher les messages d'erreur.
        stopThreadSignal (obj): Un signal pour arrêter le thread.
        
    Methods:
        EditConnected (func): Modifier la variable globale connected.
        IsConnected (func): Récupérer la variable globale connected.
        join (func): Rejoindre une room.
        close (func): Fermer la fenêtre.
        closeEvent (func): Fermer la fenêtre.
        sendMessage (func): Envoyer un message.
        restore_old_messages (func): Restaurer les anciens messages d'un salon.
        handleReceivedMessage (func): Traiter les messages reçus.
        showInfoMessage (func): Afficher un message.
        showCriticalMessage (func): Afficher un message d'erreur.
    """
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
        """
        Constructeur de la classe ChatApp.
        
        
        Classe réprésentant la fenêtre graphique du chat.
    
        Args:
            QWidget (obj): La classe parente.
            
        Attributes:
            connected (bool): Un booléen pour savoir si l'utilisateur est connecté.
            allowed_room (str): Les rooms autorisées.
            room (str): La room actuelle.
            username (str): Le nom d'utilisateur.
            last_message (str): Le dernier message envoyé.
            showMessageSignal (str): Un signal pour afficher les messages.
            showErrorMessageSignal (str): Un signal pour afficher les messages d'erreur.
            stopThreadSignal (obj): Un signal pour arrêter le thread.
            
        Methods:    
            EditConnected (func): Modifier la variable globale connected.
            IsConnected (func): Récupérer la variable globale connected.
            join (func): Rejoindre une room.
            close (func): Fermer la fenêtre.
            closeEvent (func): Fermer la fenêtre.
            sendMessage (func): Envoyer un message.
            restore_old_messages (func): Restaurer les anciens messages d'un salon.
            handleReceivedMessage (func): Traiter les messages reçus.
            showInfoMessage (func): Afficher un message.
            showCriticalMessage (func): Afficher un message d'erreur.
        """
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
       
        self.admin_panel = AdminPanel()
        self.admin_panel.show()
        
        

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
        
        self.recvthread = ReceiveThread(self)
        self.recvthread.messageReceived.connect(self.handleReceivedMessage)
        connectSignals(self)
        
        self.setGeometry(100, 100, 600, 400)

        self.show()
        
    def showInfoMessage(self, title, message):
        """
        Fonction permettant  l'émission d'un signal pour afficher un message.
        
        Args:
            title (str): Le titre du message.
            message (str): Le message.
            
        Returns:
            None
            
        Raises:
            None
        
        """
        self.showMessageSignal.emit(title, message)

    def showCriticalMessage(self, title, message):
        """
        Fonction permettant l'émission d'un signal pour afficher un message d'erreur.
        
        Args:
            title (str): Le titre du message.
            message (str): Le message.
            
        Returns:
            None
            
        Raises:
            None
        """
        
        self.showErrorMessageSignal.emit(title, message)  
        
        
    # afin d'impacter toutes les instances de ChatApp en set
    def EditConnected(self, new_value):
        """
        Fonction permettant de modifier la variable globale connected.
        
        Args:
            new_value (bool): La nouvelle valeur de la variable globale.
            
        Returns:
            None
        
        Raises:
            None
        
        """
        ChatApp.connected = new_value
    # afin d'impacter toutes les instances de ChatApp en get
    def IsConnected(self):
        """
        Fonction permettant de récupérer la variable globale connected.
        
        Args:
            None
            
        Returns:
            bool: La valeur de la variable globale.
            
        Raises:
            None
        """
        return ChatApp.connected 
        
            
    def join(self, button_room):
        """
        Fonction permettant de rejoindre une room.
        Dans le cas où l'utilisateur ne peut pas rejoindre la room, 
        une demande de souscription est envoyée au serveur.
        
        Args:
            button_room (obj): Le bouton de la room.
            
        Returns:
            None
            
        Raises:
            None
        """
        if button_room.styleSheet() == "background-color: lightgreen;":
            room = button_room.text()
            client_socket.send(f"/join {room}".encode())
        else:
            room = button_room.text()
            client_socket.send(f"/subscribe {room}".encode())
        client_socket.send("/rooms".encode()) # pour rafraîchir           
        
    def close(self):
        """
        Fonction permettant de fermer la fenêtre.
        
        Args:
            None
            
        Returns:
            super().close(): La fonction close de la classe parente.
            
        Raises:
            None
        """
        self.EditConnected = False
        #ouvrir une nouvelle instance de Login
        login = Login()
        login.setWindowTitle("Login")
        login.show()
        self.admin_panel.close()
        return super().close()
    
    def closeEvent(self, event):
        """
        Fonction d'événement accompagnant la fermeture de la fenêtre.
        
        Args:
            event (obj): L'événement.
            
        Returns:
            None
            
        Raises:
            None
        """
        self.recvthread.stop()
        client_socket.close()
        event.accept()
        
    def sendMessage(self):
        """
        Fonction permettant d'envoyer un message.
        
        Args:
            None
            
        Returns:
            None
            
        Raises:
            ConnectionAbortedError: Si la connexion est interrompue par le serveur./ 
                                    Vous avez bien été déconnecté du serveur.
        
        """

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
            self.message_list.addItem(f"{message.split(':')[0]}: {message.split(':')[1]}" \
                if message.split(':')[0] != self.username \
                    else f"Vous: {message.split(':')[1]}")
            
                    
        return 0
    
    
    def handleReceivedMessage(self, message):
        """
        Fonction permettant de traiter les messages reçus.
        
        - cmd: Si le serveur renvoie une commande.
        - scb: Si le serveur renvoie une réponse du /subscribe.
        - users: Si le serveur renvoie la liste des utilisateurs. 
                /!\ (non gérée dans GUI)
        - query: Si le serveur renvoie la liste des requêtes pour admin.
        - jn: Si le serveur renvoie la réponse du /join.
        - us: Si le serveur renvoie la réponse du /unsubscribe.
        - fwd: Si le serveur renvoie la réponse du /forward.
        - old: Si le serveur renvoie les anciens messages.
                
        Args:
            message (str): Le message reçu.
            
        Returns:
            None
            
        Raises:
            Depuis les signaux:
                - Error: Si le serveur renvoie une erreur.
                - Déconnexion: Si le serveur renvoie une déconnexion.
                
        
        """
        
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
            message = None
        
        elif message.startswith("scb:"): # le serveur renvoie la réponse du /subscribe
            message = message.split("scb:")[1]
            
            if "accept" in message:
                client_socket.send("/rooms".encode())
            else:
                client_socket.send("/rooms".encode())
            message = None
            
        elif message.startswith("users:"): # le serveur renvoie la liste des utilisateurs
            pass # Non géré (voir le client non graphique pour implémenter la logique)
        
        elif message.startswith("query:"): # le serveur renvoie la liste des requêtes pour admin
            self.admin_panel.updateUI(message) # pour mettre à jour son UI 
            message = None
        
        elif message.startswith("jn:"): # le serveur renvoie la réponse du /join
            message = message.split("jn:")[1]
            if "Succès" in message:
                self.room = message.split(":")[1]
                self.message_list.clear()
                self.message_list.addItem(f"Vous avez rejoint la room {self.room}")
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
                
            message = None
            
        elif message.startswith("us:"): # le serveur renvoie la réponse du /unsubscribe
            message = message.split("us:")[1]
            if "désabonné" in message:
                self.join(self.general_room)
            else:
                pass
            message = None
            
        elif message.startswith("fwd:"): # le serveur renvoie la réponse du /forward
            fwd_user, fwd_message = message.split("fwd:")[1].split(":")[0], message.split("fwd:")[1].split(":")[1]
            self.message_list.addItem(f"{fwd_user}: {fwd_message}")
            message = None
            
        elif message.startswith("old:"): # le serveur renvoie les anciens messages
            self.restore_old_messages(message)
            message = None
        
        if message:
            self.message_list.addItem(f"server:{message}")
            message = None
            
        return 0
                
    
def connectSignals(chat_app_instance):
    """
    Cette fonction permet de connecter les signaux entre deux classes
    
    Args:
        chat_app_instance (obj): L'instance de la classe ChatApp.
    
    Returns:
        None
        
    Raises:
        None
    
    """
    chat_app_instance.showMessageSignal.connect(chat_app_instance.showInfoMessage)
    chat_app_instance.showErrorMessageSignal.connect(chat_app_instance.showCriticalMessage)
def client_socket_create():
    """
    Fonction permettant d'initier de nouveaux sockets afin de se connecter au serveur.
    Ce socket est accessible depuis tout le programme via la variable globale client_socket.
    
    Args:
        None
        
    Returns:
        None
    
    Raises:
        None
    
    """
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    
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
        hostname, _, _ = socket.gethostbyaddr(ip_address) # le _ veut dire ne rentrer la valeur dans une variable (utilisé parfois dans les boucles)
        
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
    """
    Point d'entrée du programme client (si exécuté en script)
    
    Récupérer les arguments de la ligne de commande et lancer le programme client.
    
    Si search est activé:
        vérifier si le client s'exécute sur une machine virtuelle. Si ce n'est pas le cas, rechercher des serveurs sur le réseau local en utilisant des paquets UDP.
        Puis s'il y a un serveur trouvé, démarrer main avec l'adresse et le port du serveur.
    Sinon:
        démarrer main avec l'adresse et le port du serveur. (fournis en argument ou par défaut)
    """
    args = arg_parse()
    
    if args.search:
        vm_check = True \
        if "virtualbox" in getResults('WMIC COMPUTERSYSTEM GET MODEL').lower() \
            or getResults("WMIC BIOS GET SERIALNUMBER").split("\n")[1] == "0" \
                else False # Vérifie si le client est dans une VM ou non.
        #vm_check = False
        if not vm_check:
            c_iface = get_interface_name_by_ip(get_ip())
            print("searching for server...")
            client_ports = 9999
            filters = f"udp port {client_ports}"
            sniff(prn=handle_announcement, filter=filters, store=0, iface=c_iface, timeout=20, count=1)
            if host == None or port == None:
                print(Fore.RED + "Impossible de trouver le serveur, vérifiez que le serveur est bien lancé sur le réseau local.")
                sys.exit()
            
            
            host = args.host if host == None else host
            port = args.port if port == None else port
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
