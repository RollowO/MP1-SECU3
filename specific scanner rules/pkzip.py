import os
import yara
from tqdm import tqdm

# ================= CONFIG =================
TARGET_DRIVE = r"C:\Users\John\Desktop"
YARA_RULE_FILE = "anom.yar"
MAX_READ_BYTES = 4096   # ZIP header fits easily within this
# ==========================================


def scan_drive():
    print("[*] Compiling YARA rule...")
    rules = yara.compile(filepath=YARA_RULE_FILE)

    flagged_count = 0
    scanned_count = 0

    print(f"[*] Scanning drive: {TARGET_DRIVE}")
    
    for root, _, files in os.walk(TARGET_DRIVE):
        for file in files:
            scanned_count += 1
            full_path = os.path.join(root, file)

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
    print(f"Total files scanned: {scanned_count}")
    print(f"PKZIP files flagged: {flagged_count}")


if __name__ == "__main__":
    scan_drive()
