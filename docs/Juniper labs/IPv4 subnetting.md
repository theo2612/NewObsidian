# Example 
197            . 217            . 244            . 51
1100 0101 . 1101 1001 . 1111 0100 . 0011 0011



/26 - subnet mask
1111 1111 . 1111 1111 . 1111 1111 . 1100 0000

bitwise AND logic is: 0 AND 0 = 0 1 AND 0 = 0 0 AND 1 = 0 1 AND 1 = 1


Network
1100 0101 . 1101 1001 . 1111 0100 . 0000 0000
   197    .    217    .    244    .    0



Broadcast 
1100 0101 . 1101 1001 . 1111 0100 . 0011 1111
   197    .    217    .    244    .    63   




first host = NET + 1 
197           . 217             . 244            . 1                 

last host = BRD - 1 
197           . 217             . 244            . 62

next subnet
197           .217              . 244             .64

---
# Practice 
Target ip address

| decimal | 181       | 12        | 23        | 148       |
| ------- | --------- | --------- | --------- | --------- |
| binary  | 1011 0101 | 0000 1100 | 0001 0111 | 1001 0100 |


/19  - subnet mask

| decimal | 8         | 16        | 24        | 32        |
| ------- | --------- | --------- | --------- | --------- |
| binary  | 1111 1111 | 1111 1111 | 1110 0000 | 0000 0000 |

Network

| binary  | 1011 0101 | 0000 1100 | 0000 0000 | 0000 0000 |
| ------- | --------- | --------- | --------- | --------- |
| decimal | 181       | 12        | 0         | 0         |


Broadcast

| binary  | 1011 0101 | 0000 1100 | 0001 1111 | 1111 1111 |
| ------- | --------- | --------- | --------- | --------- |
| decimal | 181       | 12        | 31        | 255       |


First host = NET + 1

Last host = BRD - 1 

next subnet = BRD + 1

---

## Patterns to Recognize
- **Common IP Octet Values in Binary:**
- - 0 = 00000000 (all zeros)
- - 128 = 10000000 (just the first bit)
- - 192 = 11000000 (first two bits)
- - 224 = 11100000 (first three bits)
- - 240 = 11110000 (first four bits)
- - 248 = 11111000 (first five bits)
- - 252 = 11111100 (first six bits)
- - 254 = 11111110 (first seven bits)
- - 255 = 11111111 (all ones)

## Speed Tips
- **1. The Half-Way Method**
- - 128 is half of 256 (the range of one octet)
- - If a number is ≥ 128, the first bit is 1
- - Subtract 128 and repeat with 64, 32, etc.
- **2. Common Patterns**
- - 255 = all 1s (8 bits on)
- - 0 = all 0s (8 bits off)
- - Powers of 2 = only one bit on
- **3. Subnet Mask Shortcuts**
- - /24 = 255.255.255.0 (3 full octets)
- - /16 = 255.255.0.0 (2 full octets)
- - /8 = 255.0.0.0 (1 full octet)
- **4. Quick Check Method**
- - Even numbers end in 0
- - Odd numbers end in 1
- - Numbers ≥ 128 start with 1

172
1010 1100
























