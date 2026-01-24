import base64
import re

# Read and decrypt
with open('TunnyAchePlaintext.txt', 'r') as f:
    encoded_plaintext = f.read().strip()

with open('TunnyAcheCyphertext.txt', 'r') as f:
    b64_ciphertext = f.read().strip()

b64_ciphertext = b64_ciphertext.replace('\n', '').replace('\r', '').replace(' ', '')
padding = len(b64_ciphertext) % 4
if padding:
    b64_ciphertext += '=' * (4 - padding)
ciphertext = base64.b64decode(b64_ciphertext)
plaintext_bytes = encoded_plaintext.encode('ascii')
keystream = bytes([plaintext_bytes[i] ^ ciphertext[i] for i in range(len(ciphertext))])
decrypted_encoded = bytes([ciphertext[i] ^ keystream[i] for i in range(len(ciphertext))])
decrypted_encoded_text = decrypted_encoded.decode('ascii', errors='replace')

# Full plaintext with proper decoding
decoded_full = encoded_plaintext
decoded_full = decoded_full.replace('5EMW98', '.')
decoded_full = decoded_full.replace('5X8', '-')
decoded_full = decoded_full.replace('5N98', '\n')
decoded_full = decoded_full.replace('5M98', '.')
decoded_full = decoded_full.replace('5S8', "'")
decoded_full = decoded_full.replace('5C98', ':')
decoded_full = decoded_full.replace('33', '\n\n')
decoded_full = decoded_full.replace('9', ' ')

print("FULL MESSAGE (known plaintext, properly decoded):")
print("="*60)
print(decoded_full)
print("="*60)

# Search for flag patterns
flags = re.findall(r'MetaCTF\{[^}]+\}', decoded_full)
if flags:
    print(f"\n🚩 FOUND FLAGS:")
    for flag in flags:
        print(f"  {flag}")
else:
    print("\n[!] No MetaCTF{} format found")
    print("[*] Searching for other patterns...")

    # Look for capitalized words that might be encoded
    caps_words = re.findall(r'\b[A-Z]{8,}\b', decoded_full)
    if caps_words:
        print(f"\n[+] Long capitalized sequences (potential encoding):")
        for word in set(caps_words):
            print(f"  {word}")

    # Look for suspicious patterns
    if '{' in decoded_full:
        print(f"\n[+] Found curly braces - searching context...")
        for match in re.finditer(r'.{0,50}\{.{0,100}\}', decoded_full):
            print(f"  {match.group()}")
