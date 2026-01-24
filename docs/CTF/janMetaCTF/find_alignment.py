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

plaintext_bytes = encoded_plaintext.encode('ascii')

print(f"Plaintext length: {len(plaintext_bytes)}")
print(f"Ciphertext length: {len(ciphertext)}")
print(f"Difference: {len(plaintext_bytes) - len(ciphertext)} bytes")

# Try to find where they align by looking for low-entropy XOR results
# (printable ASCII should XOR to produce patterns)

# Check if they align at offset 0
print("\nTesting alignment at offset 0:")
test_len = min(100, len(plaintext_bytes), len(ciphertext))
xor_result = bytes([plaintext_bytes[i] ^ ciphertext[i] for i in range(test_len)])
print(f"XOR result (first 100 bytes): {xor_result[:100]}")

# The XOR should produce the keystream, which might have patterns
# Let's check how much of the plaintext we can actually verify
verified_length = min(len(plaintext_bytes), len(ciphertext))

# Decrypt and compare
decrypted = bytes([plaintext_bytes[i] ^ ciphertext[i] ^ plaintext_bytes[i] for i in range(verified_length)])

# Actually, let's just see what happens after our known plaintext ends
print(f"\n{'='*60}")
print("The plaintext we have goes beyond the ciphertext length")
print(f"{'='*60}")
print(f"Plaintext coverage: 0 to {len(plaintext_bytes)}")
print(f"Ciphertext coverage: 0 to {len(ciphertext)}")
print(f"\nPlaintext extends {len(plaintext_bytes) - len(ciphertext)} bytes beyond ciphertext")

# Show where plaintext ends
print(f"\nLast 100 chars of plaintext:")
print(encoded_plaintext[-100:])

# This means the ciphertext is actually SHORTER than the full message
# So we can't decrypt what we don't have
print("\n[!] The ciphertext is truncated - it doesn't contain the full message!")
print("[!] We need to find more ciphertext or the flag is in what we already decrypted")

# Let's search more carefully in what we decrypted
keystream = bytes([plaintext_bytes[i] ^ ciphertext[i] for i in range(len(ciphertext))])
decrypted_full = bytes([ciphertext[i] ^ keystream[i] for i in range(len(ciphertext))])
decrypted_text = decrypted_full.decode('ascii', errors='replace')

# Decode
decoded = decrypted_text
decoded = decoded.replace('5EMW98', '.')
decoded = decoded.replace('5X8', '-')
decoded = decoded.replace('5N98', '\n')
decoded = decoded.replace('5M98', '.')
decoded = decoded.replace('5S8', "'")
decoded = decoded.replace('5C98', ':')
decoded = decoded.replace('33', '\n\n')
decoded = decoded.replace('9', ' ')

print(f"\n{'='*60}")
print("SEARCHING FULL DECRYPTED TEXT FOR FLAG PATTERNS:")
print(f"{'='*60}")
print(decoded)
