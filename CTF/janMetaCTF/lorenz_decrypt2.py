import base64

# Read files
with open('TunnyAchePlaintext.txt', 'r') as f:
    encoded_plaintext = f.read().strip()

with open('TunnyAcheCyphertext.txt', 'r') as f:
    b64_ciphertext = f.read().strip()

# Decode ciphertext from base64
b64_ciphertext = b64_ciphertext.replace('\n', '').replace('\r', '').replace(' ', '')
padding = len(b64_ciphertext) % 4
if padding:
    b64_ciphertext += '=' * (4 - padding)
ciphertext = base64.b64decode(b64_ciphertext)

# Use the ENCODED plaintext (not decoded)
plaintext_bytes = encoded_plaintext.encode('ascii')

print(f"Encoded plaintext length: {len(plaintext_bytes)} bytes")
print(f"Ciphertext length: {len(ciphertext)} bytes")

# Extract keystream from known plaintext
min_len = min(len(plaintext_bytes), len(ciphertext))
keystream = bytes([p ^ c for p, c in zip(plaintext_bytes[:min_len], ciphertext[:min_len])])

print(f"Extracted keystream length: {len(keystream)} bytes")
print(f"Known plaintext covers {min_len} bytes of {len(ciphertext)} total ciphertext")
print(f"Unknown portion: {len(ciphertext) - min_len} bytes")

# Decrypt the FULL ciphertext using extracted keystream
decrypted_encoded = bytearray()
for i in range(len(ciphertext)):
    if i < len(keystream):
        decrypted_encoded.append(ciphertext[i] ^ keystream[i])
    else:
        # This shouldn't happen if our plaintext covers everything
        decrypted_encoded.append(ciphertext[i] ^ keystream[i % len(keystream)])

decrypted_encoded_text = decrypted_encoded.decode('ascii', errors='replace')

print(f"\n{'='*60}")
print("FULL DECRYPTED MESSAGE (still encoded):")
print(f"{'='*60}")
print(decrypted_encoded_text[:500])
print("\n[...]\n")
print(decrypted_encoded_text[-500:])

# Now decode it
decoded = decrypted_encoded_text
decoded = decoded.replace('5EMW98', '.')
decoded = decoded.replace('5X8', '-')
decoded = decoded.replace('5N98', '\n')
decoded = decoded.replace('5M98', '.')
decoded = decoded.replace('5S8', "'")
decoded = decoded.replace('5C98', ':')
decoded = decoded.replace('33', '\n\n')
decoded = decoded.replace('9', ' ')

print(f"\n{'='*60}")
print("DECODED FULL MESSAGE:")
print(f"{'='*60}")
print(decoded[-800:])

# Look for flag
import re
flags = re.findall(r'MetaCTF\{[^}]+\}', decoded)
if flags:
    print(f"\n{'='*60}")
    print("FLAGS FOUND:")
    print(f"{'='*60}")
    for flag in flags:
        print(flag)
else:
    print("\n[!] No MetaCTF{} flag found in standard format")
    print("[*] Searching for partial flags or encoded flags...")
    # Search in encoded version too
    flags_encoded = re.findall(r'MetaCTF', decrypted_encoded_text)
    if flags_encoded:
        print(f"Found 'MetaCTF' in encoded text - checking context...")
        idx = decrypted_encoded_text.find('MetaCTF')
        print(decrypted_encoded_text[idx:idx+100])
