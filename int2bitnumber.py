num = 115792089210356248762697446949407573529996955224135760342422259061068512044369  # 你要转换的整数
binary_str = bin(num)
num_bits = len(binary_str) - 2  # 减去前缀 '0b'
print(f"{num} 转换为二进制占用 {num_bits} 位。")

#test