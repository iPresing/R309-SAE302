import sys
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QGridLayout, QComboBox, QMessageBox


class MaFenetre(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Conversion de température')
        self.resize(400, 200)

        self.label = QLabel("Température")
        self.champ = QLineEdit()
        self.label2 = QLabel("°C")
        bouton = QPushButton("Convertir")
        self.label3 = QLabel("Conversion")
        self.champ2 = QLineEdit()
        self.label4 = QLabel("K")
        self.bouton_aide = QPushButton("?")

        self.qcombo = QComboBox()
        self.qcombo.setGeometry(100, 10, 150, 30)
        self.qcombo.addItems(["°C vers K", "K vers °C"])

        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.grid.addWidget(self.label, 0, 0)
        self.grid.addWidget(self.champ, 0, 1, 1, 1)
        self.grid.addWidget(self.label2, 0, 2)
        self.grid.addWidget(bouton, 1, 1, 1, 1)
        self.grid.addWidget(self.label3, 2, 0)
        self.grid.addWidget(self.champ2, 2, 1)
        self.grid.addWidget(self.label4, 2, 2)
        self.grid.addWidget(self.qcombo, 1, 3, 1, 1)
        self.grid.addWidget(self.bouton_aide, 4, 4, 1, 1)

        bouton.clicked.connect(self.conversion)

        self.qcombo.currentIndexChanged.connect(self.changement)

        self.bouton_aide.clicked.connect(self.aide)


    def conversion(self):
        try:
            Initiale = float(self.champ.text())
            option = self.qcombo.currentText()

            if option == "°C vers K":
                Convertie = Initiale + 273.15 
            elif option == "K vers °C":
                Convertie = Initiale - 273.15  
            else:
                raise ValueError("Option de conversion non prise en charge")

            self.champ2.setText(f"{Convertie:.2f}")

        except ValueError:
            self.champ2.setText("Entrez une température valide")

    def changement(self):
        if self.qcombo.currentText() == "°C vers K":
            self.label2.setText("°C")
            self.label4.setText("K")
        elif self.qcombo.currentText() == "K vers °C":
            self.label2.setText("K")
            self.label4.setText("°C")

    def aide(self):
        QMessageBox.information(self, "Aide", "Permet de convertir un nombre soit de Kelvin vers Celcius soit de Celcius vers Kelvin")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    fenetre = MaFenetre()
    fenetre.show()
    sys.exit(app.exec())
