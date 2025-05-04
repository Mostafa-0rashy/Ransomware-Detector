import re
import os

def read_yara_file_lines(file_path):
    lines = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
            lines = [line.strip() for line in raw_lines if line.strip()]
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
    return lines



def get_string_for_identifier(identifier, yara_file_path):
    # Read the YARA file lines
    lines = read_yara_file_lines(yara_file_path)

    # Initialize variables
    string_lines = []
    in_string_section = False

    # Iterate through the lines to find the string section
    for line in lines:
        if line.__contains__("strings:"):
            in_string_section = True
            continue
        if in_string_section:
            if line.__contains__("condition:"):
                break  # End of strings section
            if line.__contains__(str(identifier)):
                return line[line.index('"')+1:].strip()[:-1].split("\"")[0] # Extract the string value

    return ""
    
   
