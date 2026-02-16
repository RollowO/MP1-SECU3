import os
import yara
from tqdm import tqdm

# ================= CONFIG =================
TARGET_DRIVE = r"C:\Users\John\Desktop\File"
YARA_RULE_FILE = r"C:\Users\John\Desktop\github chatgpt\MP1-SECU3\specific scanner rules\DOSexec.yar"
MAX_READ_BYTES = 4096   # ZIP header fits easily within this
# ==========================================


def scan_drive():
    print("[*] Compiling YARA rule...")
    rules = yara.compile(filepath=YARA_RULE_FILE)

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

            matches = rules.match(data=data)

            if matches:
                flagged_count += 1
                print(f"[PKZIP] {full_path}")

        except (PermissionError, OSError):
            continue
        except Exception:
            continue

    print("\n====== Scan Complete ======")
    print(f"Total files scanned: {total_files}")
    print(f"PKZIP files flagged: {flagged_count}")


if __name__ == "__main__":
    scan_drive()
