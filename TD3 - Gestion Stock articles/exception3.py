class IncorrectPrice(Exception):
    def __init__(self, message):
        super().__init__(message)

class Article:
    TVA: int = 20
    def __init__(self, nom:str ="test", code_barre:str = "test", prixHT:int = 20):
        self.__nom = nom
        self.__code_barre = code_barre
        if prixHT != 0:
            self.__prixHT = prixHT
        else: 
            self(nom, code_barre)
    @property
    def code_barre(self):
        return self.__code_barre
    @code_barre.setter
    def code_barre(self, code_barre):
        self.__code_barre = code_barre
        
    @property 
    def nom(self):
        return self.__nom
    @nom.setter
    def nom(self, nom):
        self.__nom = nom
        
    @property
    def prixHT(self):
        return self.__prixHT
    
    @prixHT.setter
    def prixHT(self, prixHT):
        try:
            if prixHT <= 0:
                raise IncorrectPrice('Ce prix est incorrect')
        except IncorrectPrice as err:
            print("Erreur :", err)
        else:
            self.__prixHT = prixHT
            
    @property
    def prixT(self):
        prixHT = self.prixHT
        return prixHT + (prixHT * Article.TVA / 100) 

        
    
    
    
article1 = Article("test","test")

print(article1.prixHT)
            
        
    
        