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

# Decode the plaintext encoding
decoded_plaintext = encoded_plaintext
decoded_plaintext = decoded_plaintext.replace('5EMW98', '.')
decoded_plaintext = decoded_plaintext.replace('5X8', '-')
decoded_plaintext = decoded_plaintext.replace('5N98', '\n')
decoded_plaintext = decoded_plaintext.replace('5M98', '.')
decoded_plaintext = decoded_plaintext.replace('5S8', "'")
decoded_plaintext = decoded_plaintext.replace('5C98', ':')
decoded_plaintext = decoded_plaintext.replace('33', '\n\n')
decoded_plaintext = decoded_plaintext.replace('9', ' ')

# Convert to bytes
plaintext_bytes = decoded_plaintext.encode('ascii', errors='ignore')

print(f"Plaintext length: {len(plaintext_bytes)} bytes")
print(f"Ciphertext length: {len(ciphertext)} bytes")

# Extract keystream from known plaintext
min_len = min(len(plaintext_bytes), len(ciphertext))
keystream = bytes([p ^ c for p, c in zip(plaintext_bytes[:min_len], ciphertext[:min_len])])

print(f"Extracted keystream length: {len(keystream)} bytes")

# Now decrypt the ENTIRE ciphertext using the keystream
# The keystream might repeat or continue with a pattern
decrypted = bytearray()
for i in range(len(ciphertext)):
    if i < len(keystream):
        decrypted.append(ciphertext[i] ^ keystream[i])
    else:
        # Beyond our known plaintext - keystream might repeat
        # Try using the last part of keystream as pattern
        decrypted.append(ciphertext[i] ^ keystream[i % len(keystream)])

decrypted_text = decrypted.decode('ascii', errors='replace')

print(f"\n{'='*60}")
print("FULL DECRYPTED MESSAGE:")
print(f"{'='*60}")
print(decrypted_text)

print(f"\n{'='*60}")
print("LAST 500 CHARACTERS (where the flag should be):")
print(f"{'='*60}")
print(decrypted_text[-500:])

# Look for MetaCTF flag
import re
flags = re.findall(r'MetaCTF\{[^}]+\}', decrypted_text)
if flags:
    print(f"\n{'='*60}")
    print("FLAGS FOUND:")
    print(f"{'='*60}")
    for flag in flags:
        print(flag)
