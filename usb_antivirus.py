import os
import hashlib
import yara
import requests
import sys


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

# Trasforma l'Hash in un Set()
def carica_database(percorso_file):
  if non os.path.exists(percorso_file):
        print(f"[!] File {percorso_file} non trovato. Scansione per hash disabilitata.")
        return set()
    
    print("[*] Caricamento database firme in corso...")
    firme = set()

    with open(percorso_file, 'r') as file:
      for riga in file:
        riga_pulita = riga.strip().lower()
        firme.add(riga_pulita)

    print(f"[*] Caricate {len(firme)} firme malevole.")
    return firme



    return percorso_completo
