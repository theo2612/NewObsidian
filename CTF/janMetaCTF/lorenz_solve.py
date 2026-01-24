import base64

# Read files
with open('TunnyAchePlaintext.txt', 'r') as f:
    encoded_plaintext = f.read().strip()

with open('TunnyAcheCyphertext.txt', 'r') as f:
    b64_ciphertext = f.read().strip()

# Decode ciphertext from base64 (add padding if needed)
# Remove whitespace first
b64_ciphertext = b64_ciphertext.replace('\n', '').replace('\r', '').replace(' ', '')
# Add padding if needed
padding = len(b64_ciphertext) % 4
if padding:
    b64_ciphertext += '=' * (4 - padding)

try:
    ciphertext = base64.b64decode(b64_ciphertext)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
except Exception as e:
    print(f"Base64 decode error: {e}")
    print(f"Trying to decode without padding...")
    # Maybe it's not base64, let's check
    print(f"First 100 chars of ciphertext: {b64_ciphertext[:100]}")
    ciphertext = None

# Analyze plaintext encoding
print(f"\nEncoded plaintext length: {len(encoded_plaintext)} chars")
print(f"First 100 chars: {encoded_plaintext[:100]}")
print(f"Last 100 chars: {encoded_plaintext[-100:]}")

# Look for patterns
print("\nPattern analysis:")
print(f"Count of '9': {encoded_plaintext.count('9')}")
print(f"Count of '5N98': {encoded_plaintext.count('5N98')}")
print(f"Count of '5M98': {encoded_plaintext.count('5M98')}")
print(f"Count of '5S8': {encoded_plaintext.count('5S8')}")
print(f"Count of '5C98': {encoded_plaintext.count('5C98')}")
print(f"Count of '33': {encoded_plaintext.count('33')}")

# Try to decode the plaintext encoding
# Hypothesis: 9 = space, 5M98 = period, 5N98 = newline, 5S8 = apostrophe, 5C98 = colon, 33 = paragraph marker
decoded_plaintext = encoded_plaintext
decoded_plaintext = decoded_plaintext.replace('5EMW98', '.')  # Guess
decoded_plaintext = decoded_plaintext.replace('5X8', '-')     # Guess: hyphen
decoded_plaintext = decoded_plaintext.replace('5N98', '\n')   # Newline
decoded_plaintext = decoded_plaintext.replace('5M98', '.')    # Period
decoded_plaintext = decoded_plaintext.replace('5S8', "'")     # Apostrophe
decoded_plaintext = decoded_plaintext.replace('5C98', ':')    # Colon
decoded_plaintext = decoded_plaintext.replace('33', '\n\n')   # Paragraph
decoded_plaintext = decoded_plaintext.replace('9', ' ')       # Space

print(f"\nDecoded plaintext (first 200 chars):\n{decoded_plaintext[:200]}")
print(f"\nDecoded plaintext (last 200 chars):\n{decoded_plaintext[-200:]}")
print(f"\nDecoded plaintext length: {len(decoded_plaintext)} bytes")
