import sys

class NegativeValuesError(Exception): # Erreur personnalisée
    def __init__(self, message):
        super().__init__(message)
        
        
def divEntier(x: int, y: int) -> int:
    try: 
        if x < 0 | y < 0:
            raise NegativeValuesError("L'un des nombres est négatif ")
        if y == 0:
            raise ZeroDivisionError("Ne peut diviser par 0")
        if x < y:
            return 0
        else:
            x = x - y
            return divEntier(x, y) + 1
    except NegativeValuesError as e:
        print("Erreur :", e)
        return main()
    except ZeroDivisionError as e:
        print("Erreur :", e)
        return main()
        

def main():
    try:
        x = int(input(" x = "))
        y = int(input(" y = "))
    except ValueError as err:
        print("Erreur :", err)
    else:
        print("Le résultat de la division est : ", divEntier(x, y))
    finally:
        main()  # On rappelle la fonction main de manière récursive

if __name__ == '__main__':
    sys.exit(main())
    

# 1. . Que fait ce code ? -> il réplique le comportement d'une division entière
"""
2. Essayer avec deux valeurs simples (entiers et positifs) ?

print(divEntier(5,6)) -> 0
print(divEntier(6,5)) -> 1

"""