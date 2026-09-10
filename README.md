# USB Portable Antivirus (Python)

A lightweight, portable, and completely offline antivirus engine developed in Python. Designed specifically for emergencies (Incident Response), it can be run directly from a USB flash drive on any Windows system without the need to install Python or other dependencies on the target PC.

## Overview and Features
This tool automatically scans the system drive for suspicious executables and scripts, safely isolating them.
* **Offline Hash Scanning:** Ultra-fast comparison using SHA-256 backed by a local database (`hashes.txt`).
* **YARA Engine Integration:** Pattern-based heuristic detection to identify unknown threats or obfuscated scripts.
* **Automatic Quarantine:** Immediate isolation to the USB drive with extension neutralization (appending the `.infected` suffix).
* **Integrated UAC Privileges:** The executable autonomously requests Administrator permissions upon startup to operate on system directories (e.g., `System32`).

## How the Scan Engine Works
The architecture was designed to optimize resources and prevent crashes on large files or those locked by the system.
* **Block-based SHA-256 Calculation:** The file hash is calculated by loading only 64KB chunks into memory at a time (preventing RAM overload on heavy files).
* **Pre-configured YARA Rules:** The engine analyzes files looking for suspicious PowerShell executions (policy bypasses, hidden strings), shadow copy deletion attempts (Ransomware behavior), and credential dumping (e.g., Mimikatz/LSASS).
* **Exception Handling (Safe-Fail):** The engine automatically ignores system files locked or protected by Windows (`PermissionError`), smoothly moving on to the next file.

## Compilation Guide (For Developers)
The project is designed to be compiled into a single portable `.exe` file using PyInstaller.

1. **Development Requirements:** Clone the repository and ensure you have installed the dependencies (`pip install yara-python requests pyinstaller`).
2. **Required USB Structure:** For the program to work, the compiled executable file must be placed in the same folder alongside the `hashes.txt` file containing the malicious hashes (one per line).
3. **Compilation Command:** To generate the executable with an automatic privilege request (UAC), use the following command in the terminal:
   `python -m PyInstaller --onefile --clean --uac-admin usb_antivirus.py`

## Disclaimer and Security
This project was developed for purely educational and research purposes. It does not replace an EDR solution or a commercial Antivirus with real-time protection. The author declines all responsibility for any damage to systems or data loss resulting from the use of this tool.
