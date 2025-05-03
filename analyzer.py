# analyzer.py
import os
import pefile
import subprocess
import re

# Suspicious imports to detect
SUSPICIOUS_FUNCS = [
    "CreateRemoteThread", "VirtualAlloc", "VirtualFree", "WinExec",
    "ShellExecute", "InternetOpen", "InternetConnect", "URLDownloadToFile"
]

# Suspicious DLL categories
CRYPTO_DLLS = ['advapi32.dll', 'bcrypt.dll', 'ncrypt.dll', 'crypt32.dll']
FILESYS_DLLS = ['kernel32.dll', 'shell32.dll', 'shlwapi.dll', 'ntdll.dll', 'ole32.dll']
NETWORK_DLLS = ['wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'urlmon.dll', 'httpapi.dll', 'dnsapi.dll']

# Normal section names
SUS_SECTIONS = [".text", ".data", ".rsrc", ".rdata", ".reloc", ".bss"]

# Ransom note keywords
RANSOM_KEYWORDS = [
    "decrypt", "bitcoin", "ransom", "your files", "recover", "email", "payment",
     "restore", "private key", "encryption", "contact us","encrypted", "unlock","files encrypted","decryption",
]



# Score criteria
SCORES = {
    "crypto_dll": 2,
    "network_dll": 3,
    "suspicious_func": 2,
    "high_entropy": 2,
    "unusual_section": 2,
    "ransom_note": 4,
}

def extract_strings(file_path):
    try:
        output = subprocess.check_output(["strings", file_path], stderr=subprocess.DEVNULL)
        return output.decode(errors="ignore").lower().splitlines()
    except Exception:
        return []

def analyze_file(file_path):
    verdict = "BENIGN"
    reasons = []
    score = 0

    try:
        pe = pefile.PE(file_path)

        # === Suspicious DLL Imports ===
        dlls_used = []
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                dlls_used.append(dll_name)

                if dll_name in CRYPTO_DLLS:
                    score += SCORES["crypto_dll"]
                    reasons.append(f"Imports crypto-related DLL: {dll_name}")
                elif dll_name in FILESYS_DLLS:
                    reasons.append(f"Uses file system DLL: {dll_name}")
                elif dll_name in NETWORK_DLLS:
                    score += SCORES["network_dll"]
                    reasons.append(f"Imports networking DLL: {dll_name}")

                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode(errors="ignore"))

        # === Suspicious Functions ===
        for func in SUSPICIOUS_FUNCS:
            if func in imports:
                score += SCORES["suspicious_func"]
                reasons.append(f"Uses suspicious function: {func}")

        # === Weird Sections / High Entropy ===
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip('\x00')
            entropy = section.get_entropy()

            if entropy > 7.5:
                score += SCORES["high_entropy"]
                reasons.append(f"High entropy in section {name} ({entropy:.2f})")

            if name.lower() not in SUS_SECTIONS and entropy > 6:
                score += SCORES["unusual_section"]
                reasons.append(f"Unusual section: {name} with entropy {entropy:.2f}")

        # === Ransom Notes + Regex ===
        strings = extract_strings(file_path)

        for keyword in RANSOM_KEYWORDS:
            if any(keyword in s for s in strings):
                score += SCORES["ransom_note"]
                reasons.append(f"Ransom note keyword detected: '{keyword}'")
                break

    except Exception as e:
        verdict = "ERROR"
        reasons.append(str(e))
        return verdict, reasons

    reasons.append(f"Final score: {score}")
        # Final scaled score
    score_out_of_100 = int((score / 29) * 100)
    reasons.append(f"Raw score: {score} / 29")
    reasons.append(f"Normalized score: {score_out_of_100} / 100")

    # Thresholds
    if score_out_of_100 >= 40:
        verdict = "MALICIOUS"
    else:
        verdict = "BENIGN"

    return verdict, reasons
