# detector.py
import os
from analyzer import analyze_file

def scan_directory(directory):
    malicious_count = 0
    suspicious_count = 0
    benign_count = 0
    total_files = 0

    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if not os.path.isfile(path):
            continue

        total_files += 1
        verdict, reasons = analyze_file(path)
        print(f"\n[{verdict}] {filename}")
        for reason in reasons:
            print(f"  -> {reason}")

        if verdict == "MALICIOUS":
            malicious_count += 1
        elif verdict == "BENIGN":
            benign_count += 1

    print("\n--- Summary ---")
    print(f"Total files scanned: {total_files}")
    print(f"Malicious files     : {malicious_count}")
    print(f"Benign files        : {benign_count}")

if __name__ == "__main__":
    scan_directory("../samples")
