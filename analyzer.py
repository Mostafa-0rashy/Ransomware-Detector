# analyzer.py
import os
import pefile
import subprocess

# Suspicious imports to detect
SUSPICIOUS_FUNCS = [
    "CreateRemoteThread", "VirtualAlloc", "VirtualFree", "WinExec",
    "ShellExecute", "InternetOpen", "InternetConnect", "URLDownloadToFile"
]
# === Suspicious DLL categories ===
CRYPTO_DLLS = ['advapi32.dll', 'bcrypt.dll', 'ncrypt.dll', 'crypt32.dll']
FILESYS_DLLS = ['kernel32.dll', 'shell32.dll', 'shlwapi.dll', 'ntdll.dll', 'ole32.dll']
NETWORK_DLLS = ['wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'urlmon.dll', 'httpapi.dll', 'dnsapi.dll']

# Suspicious sections (very small or very large, or weird names)
SUS_SECTIONS = [".text", ".data", ".rsrc"]


# Suspicious Notes 
RANSOM_KEYWORDS = [
    "decrypt", "bitcoin", "ransom", "your files", "recover", "email", "payment",
    "readme", "restore", "private key", "encryption", "contact us"
]

def extract_strings(file_path):
    try:
        output = subprocess.check_output(["strings", file_path], stderr=subprocess.DEVNULL)
        return output.decode(errors="ignore").lower().splitlines()
    except Exception:
        return []
    
def analyze_file(file_path):
    verdict = "BENIGN"
    reasons = []

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
                    verdict = "MALICIOUS"
                    reasons.append(f"Imports crypto-related DLL: {dll_name}")
                elif dll_name in FILESYS_DLLS:
                    reasons.append(f"Uses file system DLL: {dll_name}")
                elif dll_name in NETWORK_DLLS:
                    verdict = "MALICIOUS"
                    reasons.append(f"Imports networking DLL: {dll_name}")

                # Gather imported functions
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode(errors="ignore"))

        # === Suspicious Functions ===
        for func in SUSPICIOUS_FUNCS:
            if func in imports:
                verdict = "MALICIOUS"
                reasons.append(f"Uses suspicious function: {func}")

        # === Weird Section Sizes or Names ===
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip('\x00')
            entropy = section.get_entropy()
            size = section.SizeOfRawData

            if entropy > 7.5:
                verdict = "MALICIOUS"
                reasons.append(f"High entropy in section {name} ({entropy:.2f})")

            if name.lower() not in SUS_SECTIONS and entropy > 6:
                verdict = "MALICIOUS"
                reasons.append(f"Unusual section: {name} with entropy {entropy:.2f}")

        # === Ransom Note Keyword Detection ===
        strings = extract_strings(file_path)
        for keyword in RANSOM_KEYWORDS:
            if any(keyword in s for s in strings):
                verdict = "MALICIOUS"
                reasons.append(f"Ransom note keyword detected: '{keyword}'")
                break

    except Exception as e:
        verdict = "ERROR"
        reasons.append(str(e))

    return verdict, reasons
