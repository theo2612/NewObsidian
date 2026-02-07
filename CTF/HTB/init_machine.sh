#!/bin/bash

# --- guardrail: require a box name ---
if [ -z "$1" ]; then
  echo "[!] Usage: $0 <MachineName>"
  echo "[!] Example: $0 Blackfield"
  exit 1
fi

MACHINE_NAME="$1"
BASE_DIR="$(pwd)"
BOX_DIR="${BASE_DIR}/${MACHINE_NAME}"
NOTE_FILE="${BOX_DIR}/${MACHINE_NAME}.md"

echo "[*] Initializing HTB machine: $MACHINE_NAME"

# --- create machine directory ---
mkdir -p "$BOX_DIR"

# --- create standard subdirectories ---
for dir in nmap ffuf logs loot evidence; do
  mkdir -p "${BOX_DIR}/${dir}"
done

# --- create markdown note from template ---
if [ ! -f "$NOTE_FILE" ]; then
  cp "${BASE_DIR}/template.md" "$NOTE_FILE"
  echo "[+] Created ${MACHINE_NAME}.md from template"
else
  echo "[*] ${MACHINE_NAME}.md already exists"
fi

echo "[✓] Machine setup complete:"
echo "    ${BOX_DIR}/"

