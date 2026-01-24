import base64

# Read files
with open('TunnyAchePlaintext.txt') as f:
    provided_plaintext = f.read().strip()

with open('TunnyAcheCyphertext.txt') as f:
    b64_ct = f.read().strip().replace('\n','').replace('\r','').replace(' ','')

# Decode ciphertext
padding = len(b64_ct) % 4
if padding:
    b64_ct += '=' * (4 - padding)
ct = base64.b64decode(b64_ct)

# Extract keystream using provided plaintext
pt_bytes = provided_plaintext.encode('ascii')
keystream = bytes([pt_bytes[i] ^ ct[i] for i in range(len(ct))])

# Decrypt the ciphertext to get OUR decrypted plaintext
our_decrypted = bytes([ct[i] ^ keystream[i] for i in range(len(ct))])
our_decrypted_text = our_decrypted.decode('ascii', errors='replace')

print(f"Provided plaintext length: {len(provided_plaintext)}")
print(f"Our decrypted length: {len(our_decrypted_text)}")
print(f"Ciphertext length: {len(ct)}")

# Compare them
min_len = min(len(provided_plaintext), len(our_decrypted_text))

differences = []
for i in range(min_len):
    if provided_plaintext[i] != our_decrypted_text[i]:
        differences.append((i, provided_plaintext[i], our_decrypted_text[i]))

if differences:
    print(f"\n[!] Found {len(differences)} differences!")
    print("\nFirst 50 differences:")
    for i, (pos, expected, got) in enumerate(differences[:50]):
        print(f"  Position {pos}: expected '{expected}' got '{got}'")
else:
    print("\n[*] No differences - they match perfectly!")
    print("[*] This means the plaintext file IS the correctly decrypted ciphertext")
    print("[*] The flag must be in the DECODED version of this text")

# So let's decode it properly and search VERY carefully
decoded = our_decrypted_text
decoded = decoded.replace('5M338', '.\n\n')
decoded = decoded.replace('5EMW98', '.')
decoded = decoded.replace('5X8', '-')
decoded = decoded.replace('5N98', '\n')
decoded = decoded.replace('5M98', '.')
decoded = decoded.replace('5S8', "'")
decoded = decoded.replace('5C98', ':')
decoded = decoded.replace('33', '\n\n')
decoded = decoded.replace('9', ' ')

print("\n" + "="*60)
print("FULL DECODED MESSAGE FROM CIPHERTEXT:")
print("="*60)
print(decoded)

# Search for flag
import re
flags = re.findall(r'MetaCTF\{[^}]+\}', decoded)
flags += re.findall(r'FLAG\{[^}]+\}', decoded)
flags += re.findall(r'\{[A-Za-z0-9_]{10,}\}', decoded)

if flags:
    print(f"\n🚩 FOUND FLAGS: {flags}")
