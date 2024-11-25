# 01-XOR

## 截图

如图

![image-20241125144308258](./04%20Cryptography.assets/image-20241125144308258.png)

end

# 02-Hex

## 问题描述

源码：

```py
#!/opt/pwn.college/python

import random
import sys

for n in range(10):
    print(f"Challenge number {n}...")

    key = random.randrange(1, 256)
    plain_secret = random.randrange(0, 256)
    cipher_secret = plain_secret ^ key

    print(f"The key: {key:#04x}")
    print(f"Encrypted secret: {cipher_secret:#04x}")
    answer = int(input("Decrypted secret? "), 16)
    print(f"You entered: {answer:#04x}, decimal {answer}.")
    if answer != plain_secret:
        print("INCORRECT!")
        sys.exit(1)

    print("Correct! Moving on.")

print("CORRECT! Your flag:")
print(open("/flag").read())
```

## 思路

其实执行完程序后，题目给我两个hex数据，我不知道要让我干什么。

看了看源码，才知道原来还是疑惑，而且我们的输入必须是十六进制。

本来打算手动做，后来觉得太麻烦，就直接让gpt生成一个自动化的脚本。

这个脚本还是很值得学习学习的。

## EXP

```python
hacker@cryptography~hex:~$ ipython
Python 3.11.9 (main, Apr  2 2024, 08:25:04) [GCC 13.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.24.0 -- An enhanced Interactive Python. Type '?' for help.

   ...:     # 获取 Key 和 Encrypted Secret
   ...:     child.expect(r'The key: (0x[0-9a-fA-F]+)')
   ...:     key = int(child.match.group(1), 16)
   ...: 
   ...:     child.expect(r'Encrypted secret: (0x[0-9a-fA-
   ...: F]+)')
   ...:     cipher_secret = int(child.match.group(1), 16)
   ...: 
   ...: 
   ...:     # 计算解密结果
   ...:     plain_secret = cipher_secret ^ key
   ...: 
   ...:     # 发送解密结果
   ...:     child.expect(r'Decrypted secret\? ')
   ...:     child.sendline(f'{plain_secret:#04x}')
   ...: 
   ...:     # 检查是否正确
   ...:     child.expect(r'Correct!|INCORRECT!')
   ...:     print(child.after)
   ...: 
   ...:     if "INCORRECT!" in child.after:
   ...:         print("Script failed to decrypt correctly
   ...: !")
   ...:         break
   ...: 
   ...: # 获取最终 flag
   ...: child.expect(r'CORRECT! Your flag:')
   ...: child.expect(pexpect.EOF)
   ...: print(child.before)
   ...: 
Challenge number 0...
Correct!
Challenge number 1...
Correct!
Challenge number 2...
Correct!
Challenge number 3...
Correct!
Challenge number 4...
Correct!
Challenge number 5...
Correct!
Challenge number 6...
Correct!
Challenge number 7...
Correct!
Challenge number 8...
Correct!
Challenge number 9...
Correct!

pwn.college{sROBxEuigAlcEh0OjoA7PSL5GLk.QXwMzN5wCO5IzW}



In [2]: 
```

# 03-ASCII

## 问题描述

源码：

```py
#!/opt/pwn.college/python

import random
import string
import sys

if not sys.stdin.isatty():
    print("You must interact with me directly. No scripting this!")
    sys.exit(1)

for n in range(1, 10):
    print(f"Challenge number {n}...")
    pt_chr, ct_chr = random.sample(
        string.digits + string.ascii_letters + string.punctuation,
        2
    )
    key = ord(pt_chr) ^ ord(ct_chr)

    print(f"- Encrypted Character: {ct_chr}")
    print(f"- XOR Key: {key:#04x}")
    answer = input("- Decrypted Character? ").strip()
    if answer != pt_chr:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

## 思路

和上一个一样，依旧是自动化脚本。

虽然我想到了pwntools。

这些脚本都可以好好学一学，以后是一个很好的参考工具。

## EXP

```py
import pexpect
import string

# 启动目标程序
child = pexpect.spawn('/challenge/run', encoding='utf-8')

# 准备 ASCII 字符集
ascii_set = string.digits + string.ascii_letters + string.punctuation

try:
    for _ in range(9):
        # 等待并读取挑战提示
        child.expect(r'Challenge number (\d+)...')
        print(child.after)  # 打印 Challenge 信息

        # 提取 Encrypted Character 和 XOR Key
        child.expect(r'- Encrypted Character: (.)')
        encrypted_char = child.match.group(1)

        child.expect(r'- XOR Key: (0x[0-9a-fA-F]+)')
        xor_key = int(child.match.group(1), 16)

        # 解密得到原始字符
        decrypted_char = None
        for char in ascii_set:
            if ord(char) ^ xor_key == ord(encrypted_char):
                decrypted_char = char
                break

        if decrypted_char is None:
            print("Failed to decrypt the character!")
            break

        # 提交解密答案
        child.expect(r'- Decrypted Character\? ')
        child.sendline(decrypted_char)
        print(f"Decrypted: {decrypted_char}")

        # 检查结果
        child.expect(r'Correct!|Incorrect!')
        print(child.after)
        if "Incorrect!" in child.after:
            print("Decryption failed!")
            break

    # 获取最终 Flag
    child.expect(r'You have mastered XORing ASCII! Your flag:')
    child.expect(pexpect.EOF)
    print("Flag:")
    print(child.before)

except pexpect.exceptions.EOF:
    print("Program terminated unexpectedly.")
except pexpect.exceptions.TIMEOUT:
    print("Timeout occurred. Check the script or the target program.")

```

## 截图

尽管题目不让我们使用脚本，但是还是照用不误。

![image-20241125150303055](./04%20Cryptography.assets/image-20241125150303055.png)

# 04-ASCII Strings

## 问题描述

源码

```py
#!/opt/pwn.college/python

import random
import string
import sys

from Crypto.Util.strxor import strxor

valid_keys = "!#$%&()"
valid_chars = ''.join(
    c for c in string.ascii_letters
    if all(chr(ord(k)^ord(c)) in string.ascii_letters for k in valid_keys)
)

print(valid_keys, valid_chars)

for n in range(1, 10):
    print(f"Challenge number {n}...")

    key_str = ''.join(random.sample(valid_keys*10, 10))
    pt_str = ''.join(random.sample(valid_chars*10, 10))
    ct_str = strxor(pt_str.encode(), key_str.encode()).decode()

    print(f"- Encrypted String: {ct_str}")
    print(f"- XOR Key String: {key_str}")
    answer = input("- Decrypted String? ").strip()
    if answer != pt_str:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

## 思路

依旧是gpt

## EXP

### subprocess版本

```PY
#!/opt/pwn.college/python

import subprocess
from Crypto.Util.strxor import strxor

# 模拟与挑战程序的交互
def solve_challenge():
    # 启动挑战脚本
    proc = subprocess.Popen(
        ["/challenge/run"],  # 替换为实际的脚本路径
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    while True:
        # 读取一行输出
        line = proc.stdout.readline().strip()
        if not line:
            continue
        
        print(line)  # 打印调试信息
        
        # 检查是否遇到加密字符串
        if line.startswith("- Encrypted String:"):
            ct_str = line.split(": ")[1]
            key_str = proc.stdout.readline().strip().split(": ")[1]
            
            # 解密密文
            pt_str = strxor(ct_str.encode(), key_str.encode()).decode()

            # 输入解密后的字符串
            proc.stdin.write(pt_str + "\n")
            proc.stdin.flush()
        elif "Incorrect!" in line:
            print("Failed!")
            break
        elif "Your flag:" in line:
            print(proc.stdout.read())  # 打印最终的 flag
            break

# 运行自动化脚本
if __name__ == "__main__":
    solve_challenge()

```

### pexpect版本

```py
#!/usr/bin/env python3

import pexpect
from Crypto.Util.strxor import strxor

def solve_challenge():
    # 启动挑战脚本
    proc = pexpect.spawn('/challenge/run')  # 替换为实际的脚本路径
    
    # 读取挑战过程中的输出并根据提示进行交互
    while True:
        line = proc.readline().decode('utf-8').strip()
        
        if not line:
            continue
        
        print(line)  # 打印当前的输出（调试用）
        
        if line.startswith("- Encrypted String:"):
            ct_str = line.split(": ")[1]
            key_str = proc.readline().decode('utf-8').strip().split(": ")[1]
            
            # 解密密文
            pt_str = strxor(ct_str.encode(), key_str.encode()).decode()
            print(f"Decrypted string: {pt_str}")
            
            # 输入解密后的字符串
            proc.sendline(pt_str)
        
        elif "Incorrect!" in line:
            print("Failed!")
            break
        
        elif "Your flag:" in line:
            print(proc.read().decode('utf-8'))  # 打印最终的 flag
            break

if __name__ == "__main__":
    solve_challenge()

```



# 05-Base64

## 问题描述

源码

```py
#!/opt/pwn.college/python

from base64 import b64encode

flag = open("/flag", "rb").read()

print(f"Base64-Encoded Flag: {b64encode(flag).decode()}")
```

## 思路

学着使用python来进行解码

## EXP

```py
import base64

# Base64 编码的字符串
encoded_string = "cHduLmNvbGxlZ2V7d0RhTVhSb1dzM3FXNFRLVGF1X1BTdjYzc1VKLlFYemN6TXp3Q081SXpXfQo="

# 解码 Base64 字符串
decoded_bytes = base64.b64decode(encoded_string)

# 将字节数据转换为字符串
decoded_string = decoded_bytes.decode('utf-8')

print(f"Decoded string: {decoded_string}")

```

## 截图

![image-20241125154814418](./04%20Cryptography.assets/image-20241125154814418.png)

# 06-One-time Pad



# 07-Many-time Pad

# 08-AES

# 09-AES-ECB-CPA

# 10-AES-ECB-CPA-HTTP

# 11-AES-ECB-CPA-Suffix

# 12-AES-ECB-CPA-Prefix













# 13-AES-ECB-CPA-Prefix-2

# 14-AES-ECB-CPA-Prefix-Miniboss

# 15-AES-ECB-CPA-Prefix-Boss

# 16-AES-CBC

# 17-AES-CBC Tampering

# 18-AES-CBC Resizing

# 19-AES-CBC-POA

# 20-AES-CBC-POA-Encrypt

# 21-DHKE

# 22-DHKE-to-AES

# 23-RSA 1











# 24-RSA 2

# 25-RSA Signatures

# 26-SHA 1

# 27-SHA 2

# 28-RSA 3

# 29-RSA 4

# 30-TLS 1

# 31-TLS 2

