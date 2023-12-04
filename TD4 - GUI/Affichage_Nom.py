import sys
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit

class MaFenetre(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('première fenêtre')
        self.setGeometry(100, 100, 500, 300)

        self.label = QLabel("Saisir votre nom :")
        self.champ = QLineEdit()
        bouton = QPushButton("OK")
        self.reponse = QLabel()
        bouton_arret = QPushButton("Arrêt")
        bouton.clicked.connect(self.appui_bouton_copie)
        bouton_arret.clicked.connect(self.arret)

        layout = QVBoxLayout(self)

        layout.addWidget(self.label)
        layout.addWidget(self.champ)
        layout.addWidget(bouton)
        layout.addWidget(self.reponse)
        layout.addWidget(bouton_arret)

    def appui_bouton_copie(self):
        texte = self.champ.text()
        self.reponse.setText(f"Bonjour {texte}")
        
    def arret(self):
        QCoreApplication.exit(0)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    fenetre = MaFenetre()
    fenetre.show()
    sys.exit(app.exec())
