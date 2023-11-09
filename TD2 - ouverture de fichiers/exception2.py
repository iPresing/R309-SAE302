flag = False

while not flag:
    arg = input("Emplacement / Nom fichier à ouvrir (avec extension) : ")
    try:
        file = open(arg, "r")
    except FileNotFoundError as e:
        print("Fichier non trouvé")
    except PermissionError as e:
        print("Vous ne semblez pas disposer des droits pour ouvrir ce fichier...")
    except IOError as e:
        print("Il n'est pas possible de lire/écrire le contenu du fichier...")
    except FileExistsError as e:
        print("Le fichier dans lequel vous souhaitez écrire existe déjà")
        
    else:
         print(file.read())
         flag = True
         file.close()
        
    finally:
        print("Programme fini") if flag else "" 