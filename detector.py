import os
from analyzer import analyze_file

def scan_directory(directory):
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if not os.path.isfile(path):
            continue

        verdict, reasons = analyze_file(path)
        print(f"\n[{verdict}] {filename}")
        for reason in reasons:
            print(f"  -> {reason}")

if __name__ == "__main__":
    scan_directory("../samples")
