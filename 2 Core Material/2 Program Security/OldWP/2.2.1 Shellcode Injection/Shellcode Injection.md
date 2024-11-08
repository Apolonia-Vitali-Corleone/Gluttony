# send和sendline似乎影响不大

# Challenge 1

## 源程序

我们看一下第一个执行shellcode的程序：

```c
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

void *shellcode_mem;
size_t shellcode_size;

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    puts("This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them");
    puts("as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will");
    puts("practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing");
    puts("other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.\n");
    for (int i = 3; i < 10000; i++) close(i);
    for (char **a = argv; *a != NULL; a++) memset(*a, 0, strlen(*a));
    for (char **a = envp; *a != NULL; a++) memset(*a, 0, strlen(*a));

    uint8_t shellcode[0x1000];
    shellcode_mem = (void *)&shellcode;
    printf("[LEAK] Placing shellcode on the stack at %p!\n", shellcode_mem);

    puts("In this challenge, shellcode will be copied onto the stack and executed. Since the stack location is randomized on every");
    puts("execution, your shellcode will need to be *position-independent*.\n");

    puts("Reading 0x1000 bytes from stdin.\n");
    shellcode_size = read(0, shellcode_mem, 0x1000);
    assert(shellcode_size > 0);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode_mem, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");
    ((void(*)())shellcode_mem)();
}
```

## 关键代码

关键就是这几段：

```c
	uint8_t shellcode[0x1000];
	shellcode_mem = (void *)&shellcode;
    shellcode_size = read(0, shellcode_mem, 0x1000);
    assert(shellcode_size > 0);
    print_disassembly(shellcode_mem, shellcode_size);
    puts("");
    puts("Executing shellcode!\n");
    ((void(*)())shellcode_mem)();
```

执行我们输入的字节码。

一堆`010101····`让你输入，然后你也输入`010101····`，然后这个`010101····`程序去执行你输入的`010101····`。

有意思哈。

## exp

很简单，任何指令都可以执行，所以chmod或者sendfile都可以。



# Challenge 3

无空字节shellcode





# challenge 4

不允许使用0x48，也就是一个扩展指令

```

```



# objdump

## -d

```bash
-d, --disassemble        
Display assembler contents of executable sections

#显示代码段
```



对于helloworld程序，得到的结果是：

```assembly
$ objdump -d -M intel hello
hello:     file format elf64-x86-64

Disassembly of section .init:
0000000000401000 <_init>:
······

Disassembly of section .plt:
0000000000401020 <.plt>:
······

Disassembly of section .plt.sec:
0000000000401040 <printf@plt>:
······

Disassembly of section .text:
0000000000401050 <_start>:
······

0000000000401080 <_dl_relocate_static_pie>:
······

0000000000401090 <deregister_tm_clones>:
······

00000000004010c0 <register_tm_clones>:
······

0000000000401100 <__do_global_dtors_aux>:
······

0000000000401130 <frame_dummy>:
······

0000000000401136 <main>:
  401136:	f3 0f 1e fa          	endbr64 
  40113a:	55                   	push   rbp
  40113b:	48 89 e5             	mov    rbp,rsp
  40113e:	48 8d 3d bf 0e 00 00 	lea    rdi,[rip+0xebf]        # 402004 <_IO_stdin_used+0x4>
  401145:	b8 00 00 00 00       	mov    eax,0x0
  40114a:	e8 f1 fe ff ff       	call   401040 <printf@plt>
  40114f:	b8 00 00 00 00       	mov    eax,0x0
  401154:	5d                   	pop    rbp
  401155:	c3                   	ret    
  401156:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40115d:	00 00 00 

0000000000401160 <__libc_csu_init>:
······

00000000004011d0 <__libc_csu_fini>:
······

Disassembly of section .fini:
00000000004011d8 <_fini>:
······

```



## -D

```bash
-D, 
--disassemble-all    
Display assembler contents of all sections

--disassemble=<sym>  
Display assembler contents from <sym>

类似于-d，但是本选项会对所有的sections进行反汇编，而不仅仅是那些包含指令的sections。
```



## -h

```bash
-h, --[section-]headers  
Display the contents of the section headers

#显示所有的头文件信息。
```

主要是26个头文件信息。

## -R|-r

```bash
   [-r|--reloc]
   -r
--reloc
    显示文件的重定位入口。如果和-d或者-D一起使用，重定位部分以反汇编后的格式显示出来
    
#这个感觉没啥用处，还是-R有点用
    
   [-R|--dynamic-reloc]
   -R
--dynamic-reloc
    显示文件的动态重定位入口，仅仅对于动态目标文件意义，比如某些共享库。
```

# PLT/GOT

两张图就OK：

第一次调用：

![image-20221021132732632](Shellcode%20Injection.assets/image-20221021132732632.png)

第二次调用：

![image-20221021132812883](Shellcode%20Injection.assets/image-20221021132812883.png)





# shellcode programing

shellcode教学：

# pwnlib.shellcraft

使用pwntools的shellcraft



pwnlib文件夹下：

- templates(文件夹)

  - ···

  - amd64
  - i386
  - mips
  - powerpc
  - arm
  - thumb(thumb 指令集为 arm 指令集的子集。)
  - ···

- __init__.py

- internal.py

- registers.py



## registers.py

包含对于各种arch的寄存器的初始化







## 所有模块

```python
from pwn import *

#amd64_to_i386.asm
#范例：
shellcode=shellcraft.amd64_to_i386()
'''
不需要参数
'''

bindsh.asm
cat.asm
cat2.asm
connect.asm
connectstager.asm
dupio.asm
dupsh.asm

echo.asm

egghunter.asm

findpeer.asm

findpeersh.asm

findpeerstager.asm

forkbomb.asm

forkexit.asm

getpid.asm

kill.asm

killparent.asm

listen.asm

loader.asm

loader_append.asm

membot.asm

migrate_stack.asm

mmap_rwx.asm

read.asm

read_upto.asm

readfile.asm

readinto.asm

readloop.asm

readn.asm

readptr.asm

recvsize.asm

setregid.asm

setresuid.asm

setreuid.asm

sh.asm

socket.asm

stage.asm

stager.asm
strace_dos.asm
syscall.asm
syscalls
writeloop.asm
```

### 范例

#### cat("flag", fd=1)

汇编：

```python
shellcode=shellcraft.cat("flag", fd=1)
print(shellcode)
```

输出：

```assembly
    /* push b'flag\x00' */
    push 0x67616c66
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push SYS_open /* 2 */
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
    syscall
    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push SYS_sendfile /* 0x28 */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    syscall
```

字节：

```python
shellcode=shellcraft.cat("flag", fd=1)
print(asm(shellcode))
```

输出：

```
b'hflagj\x02XH\x89\xe71\xf6\x0f\x05A\xba\xff\xff\xff\x7fH\x89\xc6j(Xj\x01_\x99\x0f\x05'
```



# 1|exit syscall

C语言代码：

```c
#include<stdio.h>
#include<string.h>

unsigned char code[]="your shell code";
main()
{
        printf("Shellcode Length: %d\n",strlen(code));
        int (*ret)()=(int(*)())code;
        ret();
}
```

asm代码：

```assembly

```





# Q:libcapstone.so.5

关于缺失libcapstone.so.5

问题：

```bash
$ ./babyshell_level1
./babyshell_level1: error while loading shared libraries: libcapstone.so.5: cannot open shared object file: No such file or directory

```

直接把服务器的那个拷贝过来，然后放进`/usr/lib/`里面，就OK了。



# Q:capstone/capstone.h

关于无法识别capstone/capstone.h

在本地服务器和pwncollege的服务器上，gcc都无法编译。

```bash
$ gcc babyshell_level1.c -o lll
/usr/bin/ld: /tmp/cc4QBwwu.o: in function `print_disassembly':
babyshell_level1.c:(.text+0x35): 
undefined reference to `cs_open'
/usr/bin/ld: babyshell_level1.c:(.text+0x6f): 
undefined reference to `cs_disasm'
/usr/bin/ld: babyshell_level1.c:(.text+0x1f7): 
undefined reference to `cs_free'
/usr/bin/ld: babyshell_level1.c:(.text+0x2a7): 
undefined reference to `cs_close'
collect2: error: ld returned 1 exit status

```

暂时无法解决这个问题。
