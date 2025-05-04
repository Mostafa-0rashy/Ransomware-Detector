import yara
import os

# Compile the YARA rule
rules = yara.compile(filepath='high_score_ransom_text_patterns.yar')

# Folder containing the EXE files
samples_folder = 'samples'

# Initialize counters
total_files = 0
matched_files = 0
unmatched_files = 0

# Loop over each file in the samples folder
for filename in os.listdir(samples_folder):
    filepath = os.path.join(samples_folder, filename)

    # Skip if not a file
    if not os.path.isfile(filepath):
        continue

    total_files += 1

    try:
        matches = rules.match(filepath=filepath)

        if matches:
            matched_files += 1
            for match in matches:
                score = len(match.strings)
                print (f"⏲️⏲️⏲️⏲️⏲️[MATCH] {match.strings}")
                print(f"[MATCH] {filename} => Score: {score}")
        else:
            unmatched_files += 1
            print(f"[NO MATCH] {filename} => Score: 0")

    except Exception as e:
        print(f"[ERROR] {filename} => {e}")

# Summary
print("\n--- Summary ---")
print(f"Total files scanned : {total_files}")
print(f"Matched files       : {matched_files}")
print(f"Unmatched files     : {unmatched_files}")
