p2 = (208, 212, 225, 206, 219, 222, 234, 219, 193, 208, 215, 193, 214, 209, 200)                                                     
p1 = (110, 87, 96, 101, 80, 66, 70, 74, 124, 75, 124, 90, 70, 76, 70)                                                                
                                                                                                                                       
flag = [''] * 30                                                                                                                     
                                                                                                                                       
# Even indices (0, 2, 4, ..., 28): XOR with 35                                                                                       
for i in range(0, 30, 2):                                                                                                            
    flag[i] = chr(p1[i // 2] ^ 35)                                                                                                   
                                                                                                                                       
# Odd indices (1, 3, 5, ..., 29): XOR with 181                                                                                       
for i in range(1, 30, 2):                                                                                                            
    flag[i] = chr(p2[i // 2] ^ 181)                                                                                                  
                                                                                                                                       
print(''.join(flag)) 

