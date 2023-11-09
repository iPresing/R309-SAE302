flag = False


while not flag:
    arg = input("Emplacement / Nom fichier à ouvrir (avec extension) : ")
    try:
        with open(arg, 'r') as f:
            for l in f:
                l = l.rstrip("\n\r")
                print(l)
    except FileNotFoundError as e:
        print("Fichier non trouvé")
    except PermissionError as e:
        print("Vous ne semblez pas disposer des droits pour ouvrir ce fichier...")
    except IOError as e:
        print("Il n'est pas possible de lire/écrire le contenu du fichier...")
    except FileExistsError as e:
        print("Le fichier dans lequel vous souhaitez écrire existe déjà")
        
    else:
         flag = True
         f.close()
        
    finally:
        print("Programme fini") if flag else ""  