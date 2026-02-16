import os
import yara
from tqdm import tqdm

# ================= CONFIG =================
TARGET_DRIVE = r"C:\Users\John"
YARA_RULE_FILE = r"C:\Users\John\Desktop\github chatgpt\MP1-SECU3\specific scanner rules\NONE.yar"
MAX_READ_BYTES = 4096   # ZIP header fits easily within this
# ==========================================


def scan_drive():
    print("[*] Compiling YARA rule...")
    
    # NEW: Define the 'filename' external variable so YARA knows it exists
    rules = yara.compile(filepath=YARA_RULE_FILE, externals={'filename': ''})

    print(f"[*] Collecting files from: {TARGET_DRIVE}")

    # Step 1: Gather all files first
    all_files = []
    for root, _, files in os.walk(TARGET_DRIVE):
        for file in files:
            all_files.append(os.path.join(root, file))

    total_files = len(all_files)
    print(f"[*] Total files found: {total_files}")
    print("[*] Starting scan...\n")

    flagged_count = 0

    # Step 2: Wrap with tqdm progress bar
    for full_path in tqdm(all_files, desc="Scanning", unit="file"):
        try:
            with open(full_path, "rb") as f:
                data = f.read(MAX_READ_BYTES)

            # NEW: Extract just the filename (e.g. '1.docx' or 'File005')
            current_filename = os.path.basename(full_path)
            
            # NEW: Pass the filename into YARA during the match
            matches = rules.match(data=data, externals={'filename': current_filename})

            if matches:
                flagged_count += 1
                print(f"\n[FileType Detected] {full_path}")

        except (PermissionError, OSError):
            continue
        except Exception:
            continue

    print("\n====== Scan Complete ======")
    print(f"Total files scanned: {total_files}")
    print(f"Type files flagged: {flagged_count}")


if __name__ == "__main__":
    scan_drive()