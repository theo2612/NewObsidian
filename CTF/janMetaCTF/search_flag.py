import base64
import re

# Read files
with open('TunnyAchePlaintext.txt', 'r') as f:
    encoded_plaintext = f.read().strip()

with open('TunnyAcheCyphertext.txt', 'r') as f:
    b64_ciphertext = f.read().strip()

# Decode ciphertext
b64_ciphertext = b64_ciphertext.replace('\n', '').replace('\r', '').replace(' ', '')
padding = len(b64_ciphertext) % 4
if padding:
    b64_ciphertext += '=' * (4 - padding)
ciphertext = base64.b64decode(b64_ciphertext)

plaintext_bytes = encoded_plaintext.encode('ascii')

# Extract keystream
keystream = bytes([plaintext_bytes[i] ^ ciphertext[i] for i in range(len(ciphertext))])

# Decrypt full ciphertext
decrypted_encoded = bytes([ciphertext[i] ^ keystream[i] for i in range(len(ciphertext))])
decrypted_encoded_text = decrypted_encoded.decode('ascii', errors='replace')

print("Searching for flag patterns in the ENCODED decrypted text...")
print(f"Length: {len(decrypted_encoded_text)}\n")

# Search for MetaCTF in encoded form
if 'MetaCTF' in decrypted_encoded_text:
    print("[+] Found 'MetaCTF' in encoded text!")
    idx = decrypted_encoded_text.find('MetaCTF')
    print(f"Context: {decrypted_encoded_text[max(0,idx-50):idx+150]}")

# Search for common flag indicators in encoded form
patterns = ['FLAG', 'KEY', 'PASSWORD', 'SECRET', 'ANSWER']
for pattern in patterns:
    if pattern in decrypted_encoded_text:
        idx = decrypted_encoded_text.find(pattern)
        print(f"[+] Found '{pattern}' at position {idx}")
        print(f"Context: {decrypted_encoded_text[max(0,idx-50):idx+100]}\n")

# Show the very end of the decrypted encoded text
print("\n" + "="*60)
print("LAST 200 CHARS OF ENCODED DECRYPTED TEXT:")
print("="*60)
print(decrypted_encoded_text[-200:])

# Now decode and search again
decoded = decrypted_encoded_text
decoded = decoded.replace('5EMW98', '.')
decoded = decoded.replace('5X8', '-')
decoded = decoded.replace('5N98', '\n')
decoded = decoded.replace('5M98', '.')
decoded = decoded.replace('5S8', "'")
decoded = decoded.replace('5C98', ':')
decoded = decoded.replace('33', '\n\n')
decoded = decoded.replace('9', ' ')

print("\n" + "="*60)
print("LAST 300 CHARS OF DECODED TEXT:")
print("="*60)
print(decoded[-300:])

# Search for any {.*} patterns
brace_patterns = re.findall(r'\{[^}]{10,}\}', decoded)
if brace_patterns:
    print("\n[+] Found brace patterns:")
    for p in brace_patterns:
        print(f"  {p}")

# Check if there's data after where known plaintext ends
print(f"\n\nKnown encoded plaintext ends at: {encoded_plaintext[-50:]}")
print(f"Decrypted ciphertext ends at: {decrypted_encoded_text[-50:]}")
