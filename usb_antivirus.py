import os
import hashlib
import yara
import requests
import sys
import shutil


# Creo una serie di regole per Yara, se qualcuno di questi comandi viene eseguito nei vari contesti, i programmi esecutori saranno ritenuti sospetti
YARA_RULES = """
rule Suspicious_PowerShell_Execution {
    strings:
        $p1 = "-nop" nocase
        $p2 = "-w hidden" nocase
        $p3 = "-enc" nocase
        $p4 = "downloadstring" nocase
        $p5 = "iex" nocase
    condition:
        all of ($p1, $p2, $p3) or ($p4 and $p5)
}

rule Ransomware_Shadow_Deletion {
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wmic shadowcopy delete" nocase
        $s3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
    condition:
        any of them
}

rule Credential_Dumping_Keywords {
    strings:
        $c1 = "sekurlsa::logonpasswords" ascii wide nocase
        $c2 = "lsass.exe" ascii wide nocase
        $c3 = "MiniDump" ascii wide
    condition:
        $c1 or ($c2 and $c3)
}
"""

# Compila le istruzioni per Yara
def get_regole_compilate():
  try:
    return yara.compile(source=YARA_RULES)
  except Exception as e:
        print(f"[!] Errore compilazione regole YARA: {e}")
        return None

# Fornisce il percorso del file di testo contenente il databse in modo generale
def percorso_database():
  # Se il programma è stato compilato in un file .exe
    if getattr(sys, 'frozen', False):
        cartella_base = os.path.dirname(sys.executable)
    # Se stai eseguendo il normale file .py
    else:
        cartella_base = os.path.dirname(os.path.abspath(__file__))
    
    # Unisce la cartella trovata con il nome del file
    percorso_completo = os.path.join(cartella_base, "hashes.txt")
    return percorso_completo

# Trasforma l'Hash in un Set()
def carica_database(percorso_file):
    if not os.path.exists(percorso_file):
        print(f"[!] File {percorso_file} non trovato. Scansione disabilitata.")
        return set()
        
    print("[*] Caricamento database firme in corso...")
    firme = set()

    with open(percorso_file, 'r') as file:
        for riga in file:
            riga_pulita = riga.strip().lower()
            firme.add(riga_pulita)

    print(f"[*] Caricate {len(firme)} firme malevole.")
    return firme



# Calcola l'hash SHA-256
def calcola_hash(filepath):
    # prende un qualsiasi file e, attraverso una formula matematica, lo trasforma in una sequenza fissa di 64 caratteri alfanumerici
    hasher = hashlib.sha256()                  
    try:
        # rb = read binary
        with open(filepath, 'rb') as f:        
            # Leggiamo 64Kb alla volta
            while chunk := f.read(65536):      
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        # Se Windows blocca la lettura diciamo semplicemente a Python di ignorarlo
        return None                


def scansiona_cartella(cartella_da_controllare, firme_locali):
    estensioni = ('.exe', '.dll', '.bat', '.ps1')

    for cartella_corrente, sottocartelle, files in os.walk(cartella_da_controllare):
        for nome_file in files:
            # Controlla se il file ha un'estensione pericolosa
            if not nome_file.lower().endswith(estensioni):
                continue # Se non è eseguibile lo salta

            # Ricostruisce il percorso esatto del file
            percorso = os.path.join(cartella_corrente,nome_file)
            # Calcola l'hash del file
            mio_hash = calcola_hash(percorso)

            # L'hash appena calcolato è nella nostra lista degli hash conosciuti cattivi?
            if mio_hash in firme_locali:
                print(f"\n[!!!] MINACCIA TROVATA: {percorso}")

                successo, risultato = metti_in_quarantena(percorso)
                
                if successo:
                    print(f"    [V] File neutralizzato e spostato in: {risultato}\n")
                else:
                    print(f"    [X] IMPOSSIBILE SPOSTARE IL FILE: {risultato}\n")

def metti_in_quarantena(percorso_file_infetto):
    # Trova la cartella base della tua chiavetta USB
    if getattr(sys, 'frozen', False):
        cartella_usb = os.path.dirname(sys.executable)
    else:
        cartella_usb = os.path.dirname(os.path.abspath(__file__))

    # Crea il percorso per la cartella "Quarantena" sulla chiavetta
    cartella_quarantena = os.path.join(cartella_usb,"Quarantena")

    # Se non esiste la cartella bisogna crearla
    if not os.path.exists(cartella_quarantena):
        os.makedirs(cartella_quarantena)

    # Estrae il nome del file dal suo percorso
    nome_file = os.path.basename(percorso_file_infetto)
    nuovo_nome = nome_file + ".infetto"

    # Crea il percorso finale di destinazione
    destinazione = os.path.join(cartella_quarantena,nuovo_nome)

    # Sposto il file
    try:
        shutil.move(percorso_file_infetto,destinazione)
        return True,destinazione
    except Exception as e:
        return False, str(e)


print("       ANTIVIRUS USB - MODALITA' OFFLINE")

# Trova il database e caricalo
percorso_database = percorso_database()
firme_caricate = carica_database(percorso_database)

if len(firme_caricate) > 0:
    # Trova in automatico il disco principale di Windows
    disco_di_sistema = os.environ.get("SystemDrive", "C:") + "\\"

    print(f"\n[*] Avvio scansione automatica completa sul disco: {disco_di_sistema}")
    print("[*] Mettiti comodo, l'operazione richiedera' del tempo...\n")

    scansiona_cartella(disco_di_sistema,firme_caricate)
    print("\n[*] Scansione automatica completata.")

