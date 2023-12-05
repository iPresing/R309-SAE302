import sys
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QGridLayout, QMessageBox
import socket, threading
class MaFenetre(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Le serveur de chat')
        self.setGeometry(100, 100, 350, 400)

        self.label = QLabel("Serveur")
        self.label2 = QLabel("Port")
        self.label3 = QLabel("Nombre de clients maximum")
        
        self.champsl1 = QLineEdit("0.0.0.0")
        self.champsl2 = QLineEdit("10000")
        self.champsl3 = QLineEdit("5")
        # champs des messages
        self.champ_msg = QLineEdit("") 
        self.champ_msg.setFixedHeight(200)
        self.champ_msg.setReadOnly(True)
        
        
        self.bouton_start = QPushButton("Démarrage du serveur")
        self.bouton_arret = QPushButton("Quitter")
        

        layout = QGridLayout()
        self.setLayout(layout)
        layout.addWidget(self.label, 0, 0)
        layout.addWidget(self.champsl1, 0, 2, 1, 2)
        layout.addWidget(self.label2, 1, 0)
        layout.addWidget(self.champsl2, 1, 2, 1, 2)
        layout.addWidget(self.label3, 2, 0)
        layout.addWidget(self.champsl3, 2, 2, 1, 2)
        layout.addWidget(self.bouton_start, 3, 0, 1, 4)
        layout.addWidget(self.champ_msg, 4, 0, 4, 4)
        layout.addWidget(self.bouton_arret, 7, 0, 1, 4)
        self.bouton_start.clicked.connect(self.start)
        self.bouton_arret.clicked.connect(self.quitter)
        
    def accept_connexion(self):
        global client_socket
        global infos_client
        while server_started:
            try:
                client_socket, infos_client = serveur_socket.accept()
            except OSError: # si le serveur est fermé , évite de faire planter le programme
                pass
            else:
                print(f"Le client {infos_client} est connecté !")
                #self.reception(client_socket)
                threading.Thread(target=self.reception, args=(client_socket,)).start()
        
    def reception(self, c_socket):
        
        message = ""
        while message != "deco-serveur" and server_started:
            message = client_socket.recv(1024).decode()
            print(f"Le client {infos_client} dit : {message}")
            # ajouter ce message aux précédents (dans le champs)
            self.champ_msg.setText(self.champ_msg.text() + " " + message)
        c_socket.close()
        
    def start(self):
        global serveur_socket
        global server_started
        # host un socket avec les informations fournies
        host = self.champsl1.text()
        port = self.champsl2.text()
        nb_clients_max = self.champsl3.text()
        
        if self.bouton_start.text() == "Démarrage du serveur":
            server_started = True
            serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serveur_socket.bind((host, int(port)))
            serveur_socket.listen(int(nb_clients_max))
            #self.accept_connexion() # version non threaded
            accept_connexion_thread = threading.Thread(target=self.accept_connexion)
            accept_connexion_thread.start()
            self.bouton_start.setText("Arrêt du serveur")
        else:
            server_started = False
            try:
                serveur_socket.close()
            except Exception:
                pass
            self.bouton_start.setText("Démarrage du serveur")
            
    def quitter(self):
        if server_started:
            serveur_socket.close()
        else:
            pass
        QCoreApplication.instance().quit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    fenetre = MaFenetre()
    fenetre.show()
    sys.exit(app.exec())

