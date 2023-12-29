# Ce fichier permet de mettre en place les variables d'environnements, de créer l'environnement virtuel etc.


# Définir les variables d'environnement sur le système

import os
import argparse
import sys
import time

# Définir les variables d'environnement


def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="AES_KEY", default="N|ix4sqJ`y#u^8Nrn{8I[rCj]Ih_h0d[")
    parser.add_argument("-i", "--iv", help="AES_IV", default="3lV7k3}k6c0>n8da")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = arg_parse()
    AES_KEY = args.key
    AES_IV = args.iv
    
    # Si toutes les valeurs sont des valeurs par défaut demander si il ne veut pas les changer en exécutant le script avec des arguments
    
    if AES_KEY == "N|ix4sqJ`y#u^8Nrn{8I[rCj]Ih_h0d[" and AES_IV == "3lV7k3}k6c0>n8da":
        print("Voulez vous changer les valeurs par défaut (recommandé) ? (Y/n)", end=" ")
        if input().lower() == "y":
            print("Faites bien attention aux valeurs que vous vous apprêtez à entrer !\nAppuyez sur entrée pour laisser les valeurs par défaut")
            AES_KEY = input("AES_KEY : ") or AES_KEY
            AES_IV = input("AES_IV : ") or AES_IV
            # relancer le script avec l'argument -h
            print("\n Vous pouvez aussi spécifier ces valeurs en exécutant le script avec les arguments -k, -i et -db : \n")
            os.system(f"python3 {sys.argv[0]} -h")
            pass
        else:
            pass


    """
    os.system(f'setx AES_KEY "{AES_KEY}"') if os.name == 'nt' \
        else os.system(f'export AES_KEY={AES_KEY}')
    os.system(f'setx AES_IV "{AES_IV}"') if os.name == 'nt' \
        else os.system(f'export AES_IV={AES_IV}')
    os.system(f'setx MYSQL_PASSWD "{DB_PASSWORD}"') if os.name == 'nt' \
        else os.system(f'export MYSQL_PASSWD={DB_PASSWORD}')
    """
    
    # sauvegarder ces variables dans un fichiers  .env qui sera chargé par les scripts grâce à dotenv
    with open(".env", "w") as file:
        file.write(f"AES_KEY={AES_KEY}\n")
        file.write(f"AES_IV={AES_IV}\n")
        file.close()
    
    
    
    # Créer les variables contenants les scripts

    scripts = [".\\client.py", ".\\GUI\\gui.py" ]
    #scripts = [".\\server.py" ]


    # remplacer les "\" par "/" si l'OS est différent de windows
    if os.name != "nt":
        for i in range(len(scripts)):
            scripts[i] = scripts[i].replace("\\", "/")
    else:
        pass



    # Création du chemin pour l'environnement virtuel dans %APPDATA%
    venvPath = os.environ['APPDATA'] + "\\seleenix_venv" if os.name == 'nt' \
        else os.environ['HOME'] + "/seleenix_venv"


    #Créer une l'environnement virtuel python
    os.system(f"python3 -m venv {venvPath}") if os.name != "nt" \
        else os.system(f"py -m venv {venvPath}")

    # installer gsudo avec winget
    #os.system("winget install gsudo -e --disable-interactivity") if os.name == "nt" else None


    # installer les dépendances dans requirements.txt
    os.system(f"{venvPath}\\Scripts\\pip install -r requirements.txt") if os.name == "nt" \
        else os.system(f"{venvPath}/bin/pip3 install -r requirements.txt")
    

    # Itérer dans la liste

    for script in scripts:
        
        # Si sur Windows alors créer un script batch appelant le script python (dans un environnement virtuel) avec arguments
        if os.name == "nt":
            
            script_name = script.split("\\")[-1]
            exe_name = "s_" + script_name.split(".")[0] + ".exe"
            
            file_payload = f"""
            @echo off
            setlocal enabledelayedexpansion

            REM Vérifie s'il y a au moins un argument
            if "%~1"=="" (
                call {os.path.join(venvPath, "Scripts", "activate.bat")}
                call {os.path.join(venvPath, "Scripts", "python.exe")} {os.path.join(venvPath, "Scripts", script_name)}
                goto :eof
            )

            REM Initialise la variable avec le premier argument
            set "arguments=!%1!"

            REM Parcours les arguments à partir du deuxième
            shift
            :loop
            if "%~0"=="" (
                goto :done
            ) else (
                set "arguments=!arguments! %0"
                shift
                goto :loop
            )

            :done
            
            call {os.path.join(venvPath, "Scripts", "activate.bat")}
            
            call {os.path.join(venvPath, "Scripts", "python.exe")} {os.path.join(venvPath, "Scripts", script_name)} %arguments%
            
            endlocal
            """
            
            with open("s_"+ script_name.split(".")[0] + ".bat", "w") as file:
                #file.write(f'{os.path.join(venvPath, "Scripts", "activate.bat")}\n')
                #file.write(rf'{os.path.join(venvPath, "Scripts", "python.exe")} {os.path.join(venvPath, "Scripts", script_name)} %*')
                file.write(file_payload)
                
                file.close()
                
            time.sleep(2)
                
            # Puis le compiler en .exe avec b2exe
            os.system(f"b2exe /bat s_{script_name.split('.')[0]}.bat /exe {exe_name} /x64 /overwrite")
            #Supprimer le script batch
            #os.remove(script_name.split(".")[0] + ".bat")
            
            
        else:
            # Si sur Linux alors créer un script bash appelant le script python (dans un environnement virtuel) avec arguments
            script_name = script.split("/")[-1]
            print(script_name)
            with open(script_name.split(".")[0] + ".sh", "w") as file:
                file.write("#!/bin/bash\n")
                file.write(f"source {venvPath}/bin/activate\n")
                file.write(f"{venvPath}/bin/python {os.path.join(venvPath, 'bin', script_name)} $@")
                file.close()
                
            # Puis le rendre exécutable
            os.system(f"chmod +x {script_name.split('.')[0]}.sh")
            
            # Supprimer le script bash
            #os.remove(script_name.split(".")[0] + ".sh")
            
            
    # Déplacer tous les fichiers .exe dans le venvPath\Scripts\
        
    for name in scripts:
        name = name.split("\\")[-1].split(".")[0] if os.name == "nt" else \
            name.split("/")[-1].split(".")[0]
        
        os.system(f"xcopy {'s_' + name if os.name == 'nt' else name}.exe C:\\WINDOWS\\System32\\ /y") if os.name == "nt" \
            else os.system(f"cp {name}.sh /usr/bin/{name}")
        if not name == "gui":
            os.system(f"xcopy {name}.py {venvPath}\\Scripts\\ /y") if os.name == "nt"\
                else os.system(f"cp *.py /{venvPath}/bin/")
        else:
            pass
            
    # Déplacer fichier .env dans le venvPath\Scripts\
    os.system(f"move .\\.env {venvPath}\\Scripts\\ /y") if os.name == "nt" \
        else os.system(f"mv .env /{venvPath}/bin/")
    
    
      
    # Faire un déplacement pour l'application graphique dans le dossier GUI
    os.system(f"xcopy .\\GUI\\*.py {venvPath}\\Scripts\\ /y") if os.name == "nt" \
        else os.system(f"mv GUI/*.py /{venvPath}/bin/")
       
    os.system(f'del *.bat') if os.name == "nt" \
        else os.system(f'rm *.sh')
        
        
    print(f"Installation terminée ! \n Vous pouvez maintenant appeler votre script sans le préfixe python \n ex : s_client -h (windows) | client -h (mac)")
