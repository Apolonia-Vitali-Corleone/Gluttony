# 1.exit
题目描述说的很明白
```bash
hacker@building-a-web-server-level-1:/challenge$ ./run 
===== Welcome to Building a Web Server! =====
In this series of challenges, you will be writing assembly to interact with your environment, and ultimately build a web server
In this challenge you will exit a program.

Usage: `/challenge/run <path_to_web_server>`

$ cat server.s
.intel_syntax noprefix
.globl _start

.section .text

_start:
    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall

.section .data

$ as -o server.o server.s && ld -o server server.o

$ strace ./server
execve("./server", ["./server"], 0x7ffccb8c6480 /* 17 vars */) = 0
exit(0)                                 = ?
+++ exited with 0 +++

$ /challenge/run ./server
```
无非创建文件，按照它描述的指令一步一步写出来。

## build文件

```shell
#!/bin/bash

# Check if a file argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <filename.s>"
    exit 1
fi

# Get the base name of the file without extension
base_name="${1%.s}"

# Remove the first two characters from the base name
base_name="${base_name:2}"
echo "[info-gcy] base_name:$base_name"
# Assemble and link the specified file
as -o "${base_name}.o" "$1"
ld -o "$base_name" "${base_name}.o"

# Run the executable with strace
echo "[info-gcy] Running strace on $base_name:"
strace "./$base_name"
echo "[info-gcy] Completed strace on $base_name."
```




# 2.socket
本来很不理解到底干嘛，看了视频才知道，是用汇编调用一次socket，然后调用exit

```assembly
.intel_syntax noprefix
.global _start

.section .text

_start:
    #2,1,0
    mov rdi , 2
    mov rsi , 1
    mov rdx , 0
    mov rax , 0x29 #SYS_socket
    syscall

    mov rdi , 0
    mov rax , 60 #SYS_exit
    syscall 

.section .data

```

然后还是编译，执行。
关键是：

```python
[✓] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[✓] exit(0) 
```
当然，我们自己写的socket，肯定就是3，因为0,1,2,系统给占据了。
然后就是个退出。

注意下面这张图片



# 3.bind

描述：

```
Program that binds a socket
```

思路：

```
继续延续汇编代码编写
```

关键点是：

`mov rsi, offset addr`:即如何获取到

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
    # Step 1: 创建一个 socket
    mov rdi, 2                  # 参数 domain = AF_INET (2)
    mov rsi, 1                  # 参数 type = SOCK_STREAM (1)
    mov rdx, 0                  # 参数 protocol = IPPROTO_IP (0)
    mov rax, 41                 # 系统调用号 for socket
    syscall                     # 调用 socket 系统调用
    mov rdi, rax                # 将返回的 socket 文件描述符存入 rdi

    # Step 2: 绑定 socket
    mov rsi, offset addr               # rsi 指向 sockaddr_in 的地址
    mov rdx, 16                 # addrlen = sizeof(struct sockaddr_in) = 16 字节
    mov rax, 49                 # 系统调用号 for bind
    syscall                     # 调用 bind 系统调用

    # Step 3: 退出程序
    mov rdi, 0                  # exit code 0
    mov rax, 60                 # 系统调用号 for exit
    syscall                     # 调用 exit 系统调用

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        .long 0x00000000        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .quad 0                 # __pad = 填充字段 (8字节)

```



# 4.listen

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
    # Step 1: 创建一个 socket
    mov rdi, 2                  # 参数 domain = AF_INET (2)
    mov rsi, 1                  # 参数 type = SOCK_STREAM (1)
    mov rdx, 0                  # 参数 protocol = IPPROTO_IP (0)
    mov rax, 41                 # 系统调用号 for socket
    syscall                     # 调用 socket 系统调用
    mov rdi, rax                # 将返回的 socket 文件描述符存入 rdi

    # Step 2: 绑定 socket
    mov rsi, offset addr               # rsi 指向 sockaddr_in 的地址
    mov rdx, 16                 # addrlen = sizeof(struct sockaddr_in) = 16 字节
    mov rax, 49                 # 系统调用号 for bind
    syscall                     # 调用 bind 系统调用

    # Step 3:listen
    mov rsi, 0                  # max backlog
    mov rax, 50
    syscall

    # Step 3: 退出程序
    mov rdi, 0                  # exit code 0
    mov rax, 60                 # 系统调用号 for exit
    syscall                     # 调用 exit 系统调用

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        .long 0x00000000        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .quad 0                 # __pad = 填充字段 (8字节)

```



# 5.accept

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
    # Step 1: 创建一个 socket
    # 参数 domain = AF_INET (2)
    # 参数 type = SOCK_STREAM (1)
    # 参数 protocol = IPPROTO_IP (0)
    # 系统调用号 for socket
    # 调用 socket 系统调用
    # 将返回的 socket 文件描述符存入 rdi
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41                 
    syscall                     
    mov rdi, rax                

    # Step 2: bind socket
    # rsi 指向 sockaddr_in 的地址
    # addrlen = sizeof(struct sockaddr_in) = 16 字节
    # 系统调用号 for bind
    # 调用 bind 系统调用
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49                 
    syscall                     

    # Step 3:listen
    # rdi, socket file description : 3
    # rsi, max backlog : null
    mov rsi, 0                  
    mov rax, 50
    syscall
    

	# Step 4:accept
	# rdi, socket file description : 3
	# rsi, sockaddr : null
	# rdx, addrlen : null
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43
	syscall


    # Step 5: exit
    # exit code 0
    # 系统调用号 for exit
    # 调用 exit 系统调用
    mov rdi, 0                  
    mov rax, 60                 
    syscall                     


.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        .long 0x00000000        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .quad 0                 # __pad = 填充字段 (8字节)

```



# 6.statically responds

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
    # Step 1: 创建一个 socket
    #
    # 参数 domain = AF_INET (2)
    # 参数 type = SOCK_STREAM (1)
    # 参数 protocol = IPPROTO_IP (0)
    # 系统调用号 for socket
    # 调用 socket 系统调用
    # 将返回的 socket 文件描述符存入 rdi
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41                 
    syscall                     
    mov rdi, rax                

    # Step 2: bind socket
    # 
    # rsi 指向 sockaddr_in 的地址
    # addrlen = sizeof(struct sockaddr_in) = 16 字节
    # 系统调用号 for bind
    # 调用 bind 系统调用
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49                 
    syscall                     

    # Step 3:listen
    #
    # rdi, socket file description : 3
    # rsi, max backlog : null
    mov rsi, 0                  
    mov rax, 50
    syscall
    

	# Step 4:accept
	#
	# rdi, socket file description : 3
	# rsi, sockaddr : null
	# rdx, addrlen : null
	# return, fd of client : 4
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43
	syscall

	# Step 5:read
	#
	# rdi, file description
	# rsi, buffer to store the request
	# rdx, length
	mov rdi, rax
	mov rsi, offset buffer
	mov rdx, 1024
	mov rax, 0
	syscall
	
	# Step 6:write
	# 
	# rdi, file description : 4
	# rsi, buffer of the request : http...
	# rdx, length : 19
	mov rsi, offset req
	mov rdx, 19
	mov rax, 1
	syscall	
	
	# Step 7:close
	#
	# rdi, file description : 4
	mov rax, 3
	syscall	
	
    # Step 8: exit
    # exit code 0
    # 系统调用号 for exit
    # 调用 exit 系统调用
    mov rdi, 0                  
    mov rax, 60                 
    syscall                     


.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
	
	req:
		.string "HTTP/1.0 200 OK\r\n\r\n"

.section .bss
buffer: .skip 1024             # Buffer to store the request

```



# 7.dynamically responds

exp:

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
	# Step 1: create a socket
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41                 
    syscall                     
    mov rdi, rax                

    # Step 2: bind socket
    mov rdi, rdi
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49                 
    syscall                     

    # Step 3:listen
    mov rdi, rdi
    mov rsi, 0                  
    mov rax, 50
    syscall
    
	# Step 4:accept
	mov rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43
	syscall

	# Step 5:read
	mov rdi, rax
	mov rsi, offset request_buffer
	mov rdx, 1024
	mov rax, 0
	syscall
	mov r10, rdi
	
	# Step 6
	#复制动态请求的filename
	mov rdi, offset request_buffer
	add rdi, 4
	mov rsi, offset open_path
	xor rcx, rcx
	
copy_loop:
	movb al, [rdi + rcx]
	cmp al, ' '
	je done_copy
	movb [rsi + rcx], al
	inc rcx
	jmp copy_loop

done_copy:
	movb byte [rsi + rcx], 0

	# Step 6:open
	mov rdi, offset open_path
	mov rsi, 0 # mode:O_RDONLY
	mov rax, 2
	syscall	
	
	# Step 7:read
	mov rdi, rax
	mov rsi, offset second_read_file_buffer
	mov rdx, 1024
	mov rax, 0
	syscall	
	
    mov r12, rax

    # Step 8: close
    mov rdi, rdi
    mov rax, 3                 
    syscall                     

    # Step 9: write
    mov rdi, r10
    mov rsi, offset response
    mov rdx, 19
    mov rax, 1                 
    syscall
    
    # Step 10: write
    mov rdi, rdi
    mov rsi, offset second_read_file_buffer
    mov rdx, r12
    mov rax, 1                
    syscall
    
    # Step 11: close
    mov rdi, rdi
    mov rax, 3
    syscall
    
    # Step 12: exit
    mov rdi, 0
    mov rax, 60
    syscall

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
	
	response:
		.string "HTTP/1.0 200 OK\r\n\r\n"

.section .bss
request_buffer: .skip 1024
open_path: .skip 1024
second_read_file_buffer: .skip 1024
write_file_buffer: .skip 1024

```



# 8

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
	# Step 1: create a socket
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41                 
    syscall                     
    
    #放入第一个文件描述符
    push rax
    # stack 
	# 3 rsp

    # Step 2: bind socket
    mov rdi, [rsp]
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49                 
    syscall                     

    # Step 3:listen
    mov rdi, rdi
    mov rsi, 0                  
    mov rax, 50
    syscall
    
	# Step 4:accept
	mov rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43
	syscall
	
	# 放入第二个文件描述符
	push rax 
	# stack 
	# 4 rsp
	# 3

	# Step 5:read
	mov rdi, [rsp]
	mov rsi, offset request_buffer
	mov rdx, 1024
	mov rax, 0
	syscall

	#复制动态请求的filename
	mov rdi, offset request_buffer
	add rdi, 4
	mov rsi, offset open_path
	xor rcx, rcx
	
copy_loop:
	movb al, [rdi + rcx]
	cmp al, ' '
	je done_copy
	movb [rsi + rcx], al
	inc rcx
	jmp copy_loop

done_copy:
	movb byte [rsi + rcx], 0

	# Step 6:open
	mov rdi, offset open_path
	mov rsi, 0 # mode:O_RDONLY
	mov rax, 2
	syscall
	
	# 放入第三个文件描述符
	push rax
	# stack
	# 5 rsp
	# 4 
	# 3
	
	# Step 7:read
	mov rdi, rax
	mov rsi, offset read_file_buffer
	mov rdx, 1024
	mov rax, 0
	syscall
	
	# 压入读取的内容的长度
	push rax
	# stack
	# length rsp
	# 5
	# 4 
	# 3

    # Step 8: close
    mov rdi, rdi
    mov rax, 3                 
    syscall
    # 文件描述符5被关闭
    pop rax
    pop rbx
    push rax
	# Stack:
	# length <-- rsp
	# 4
	# 3

    # Step 9: write
    mov rdi, [rsp+8]
    mov rsi, offset response
    mov rdx, 19
    mov rax, 1                 
    syscall
    
    # Step 10: write
    mov rdi, rdi
    mov rsi, offset read_file_buffer
    mov rdx, [rsp]
    mov rax, 1                
    syscall
    
    # Step 11: close
    mov rdi, rdi
    mov rax, 3
    syscall
    
    # 文件描述符4被关闭
    pop rax
    pop rax
	# Stack:
	# 3 <-- rsp

    # Step 12:accept(3, null, null)
	mov rdi, [rsp]
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43
	syscall

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
	
	response:
		.string "HTTP/1.0 200 OK\r\n\r\n"

.section .bss
request_buffer: .skip 1024
open_path: .skip 1024
read_file_buffer: .skip 1024
write_file_buffer: .skip 1024

```

使用栈来存放数据，注意，rsp始终指向栈顶（不是空，就是栈顶，是有数据的）

# 9

exp

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
	#socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41 # syscall socket                 
    syscall                     
    
    push rax 
    #Stack
    # rsp --> [socket_fd]

    #bind(3,0.0.0.0:80)
    mov rdi, [rsp]
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49 # syscall accept
    syscall                     

    #listen(3, 0) = 0
    mov rdi, [rsp]
    mov rsi, 0                  
    mov rax, 50 # syscall accept
    syscall

accept_loop:
	#accept(3, NULL, NULL) = 4
	mov rdi, [rsp]
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43 # syscall accept
	syscall
	
	
    push rax
    #Stack
    # rsp --> [accept_fd, socket_fd]

	#fork() = <fork_result>
	mov rax, 57
	syscall

	test rax, rax
	jg parent_process
	je child_process

parent_process:
    #close(4) = 0
    mov rdi, [rsp]
    mov rax, 3 # Syscall close                
    syscall
    
    pop rax
    #Stack
    # rsp --> [socket_fd]
  
  	#accept(3, NULL, NULL) = ?
    jmp accept_loop

child_process:
    #Stack
    # rsp --> [accept_fd, socket_fd]

    #close(3) = 0
    mov rdi, [rsp + 8]
    mov rax, 3 # syscall: close
    syscall
    
    pop rax
    pop rbx
    push rax
    
    #Stack
    # rsp --> [accept_fd]
	
	# read(4, <rr>, <rrc>)=length
	mov rdi, [rsp]
	mov rsi, offset request_buffer
	mov rdx, 1024
	mov rax, 0 #Syscall:read
	syscall

	#复制动态请求的filename
	mov rdi, offset request_buffer
	mov rsi, offset open_path
	xor rcx, rcx
	
prepare_copy_loop:
	movb al, [rdi + rcx]
	cmp al, ' '
	je ready_for_copy
	inc rcx
	jmp prepare_copy_loop

ready_for_copy:
	inc rcx
	xor rdx, rdx
	
copy:
	movb al, [rdi + rcx]
	cmp al, ' '
	je done_copy
	movb [rsi + rdx], al
	inc rdx
	inc rcx
	jmp copy

done_copy:
	movb byte [rsi + rdx], 0

	# open("<open_path>", O_RDONLY) = 3
	mov rdi, offset open_path
	mov rsi, 0 # mode:O_RDONLY
	mov rax, 2
	syscall
	
	push rax
	
	#Stack
    # rsp --> [open_fd, accept_fd]
	
	# read(3, <read_file>, <read_file_count>) = <read_file_result>
	mov rdi, [rsp]
	mov rsi, offset read_file_buffer
	mov rdx, 1024
	mov rax, 0 # Syscall:read
	syscall
	
	push rax
		#Stack
    # rsp --> [length, open_fd, accept_fd]
	
	# close(3) = 0
	mov rdi, [rsp + 8]
	mov rax, 0x3 # Syscall:close
	syscall
	
	# write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
	mov rdi, [rsp + 16]
	mov rsi, offset response
	mov rdx, 19
	mov rax, 1
	syscall
	
	# write(4, <write_file>, <write_file_count>)=<write_file_result>
	mov rdi, rdi
	mov rsi, offset read_file_buffer
	mov rdx, [rsp]
	mov rax, 1
	syscall
	
	# exit(0) = ?
	mov rdi, 0
	mov rax, 60
	syscall

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
    response:
		.string "HTTP/1.0 200 OK\r\n\r\n"
	

.section .bss
	request_buffer: .skip 1024
	open_path: .skip 1024
	read_file_buffer: .skip 1024
	
```



# 10

10

```assembly
.intel_syntax noprefix
.global _start

.section .text
_start:
	#socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
    mov rdi, 2                  
    mov rsi, 1                  
    mov rdx, 0                  
    mov rax, 41 # syscall socket                 
    syscall                     
    
    push rax 
    #Stack
    # rsp --> [socket_fd]

    #bind(3,0.0.0.0:80)
    mov rdi, [rsp]
    mov rsi, offset addr        
    mov rdx, 16                 
    mov rax, 49 # syscall accept
    syscall                     

    #listen(3, 0) = 0
    mov rdi, [rsp]
    mov rsi, 0                  
    mov rax, 50 # syscall accept
    syscall

accept_loop:
	#accept(3, NULL, NULL) = 4
	mov rdi, [rsp]
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 43 # syscall accept
	syscall
	
	
    push rax
    #Stack
    # rsp --> [accept_fd, socket_fd]

	#fork() = <fork_result>
	mov rax, 57
	syscall

	test rax, rax
	jg parent_process
	je child_process

parent_process:
    #close(4) = 0
    mov rdi, [rsp]
    mov rax, 3 # Syscall close                
    syscall
    
    pop rax
    #Stack
    # rsp --> [socket_fd]
  
  	#accept(3, NULL, NULL) = ?
    jmp accept_loop

child_process:
    #Stack
    # rsp --> [accept_fd, socket_fd]

    #close(3) = 0
    mov rdi, [rsp + 8]
    mov rax, 3 # syscall: close
    syscall
    
    pop rax
    pop rbx
    push rax
    
    #Stack
    # rsp --> [accept_fd]
	
	# read(4, <rr>, <rrc>)=length
	mov rdi, [rsp]
	mov rsi, offset request_buffer
	mov rdx, 1024
	mov rax, 0 #Syscall:read
	syscall

	#复制动态请求的filename
	mov rdi, offset request_buffer
	mov rsi, offset open_path
	xor rcx, rcx
	
prepare_copy_loop:
	movb al, [rdi + rcx]
	cmp al, ' '
	je ready_for_copy
	inc rcx
	jmp prepare_copy_loop

ready_for_copy:
	inc rcx
	xor rdx, rdx
	
copy:
	movb al, [rdi + rcx]
	cmp al, ' '
	je done_copy
	movb [rsi + rdx], al
	inc rdx
	inc rcx
	jmp copy

done_copy:
	movb byte [rsi + rdx], 0

	# open("<open_path>", O_RDWR) = 3
	mov rdi, offset open_path
	mov rsi, 0x41 # O_WRONLY | O_CREAT
	mov rdx, 0777
	mov rax, 2
	syscall
	
	push rax
	
	#Stack
    # rsp --> [open_fd, accept_fd]
	
	# read(3, <read_file>, <read_file_count>) = <read_file_result>
	mov rdi, [rsp]
	mov rsi, offset read_file_buffer
	mov rdx, 1024
	mov rax, 1 # Syscall:write
	syscall
	
	push rax
		#Stack
    # rsp --> [length, open_fd, accept_fd]
	
	# close(3) = 0
	mov rdi, [rsp + 8]
	mov rax, 0x3 # Syscall:close
	syscall
	
	# write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
	mov rdi, [rsp + 16]
	mov rsi, offset response
	mov rdx, 19
	mov rax, 1
	syscall
	
	# write(4, <write_file>, <write_file_count>)=<write_file_result>
	mov rdi, rdi
	mov rsi, offset read_file_buffer
	mov rdx, [rsp]
	mov rax, 1
	syscall
	
	# exit(0) = ?
	mov rdi, 0
	mov rax, 60
	syscall

.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .byte 2    
        .byte 0
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
    response:
		.string "HTTP/1.0 200 OK\r\n\r\n"
	

.section .bss
	request_buffer: .skip 1024
	open_path: .skip 1024
	read_file_buffer: .skip 1024
	
```



# 11

exp

```assembly


#复制动态请求的filename
	mov rdi, offset request_buffer
	mov rsi, offset open_path
	xor rcx, rcx
	
prepare_copy_loop:
	movb al, [rdi + rcx]
	cmp al, ' '
	je ready_for_copy
	inc rcx
	jmp prepare_copy_loop

ready_for_copy:
	inc rcx
	xor rdx, rdx
	
copy:
	movb al, [rdi + rcx]
	cmp al, ' '
	je done_copy
	movb [rsi + rdx], al
	inc rdx
	inc rcx
	jmp copy

done_copy:
	movb byte [rsi + rdx], 0

cmp_get_or_post:
	# 比较第一个字符即可
	mov rdi, addr_of_data_be_read
	movb al, [rdi]
	cmp al, 'G'
	je deal_with_get
	jmp deal_with_post

deal_with_get:
	# open("<open_path>", O_RDONLY) = 3
	mov rdi, offset open_path
	mov rsi, 0 # mode:O_RDONLY
	mov rax, 2
	syscall
	
	push rax
	
	#Stack
    # rsp --> [open_fd, accept_fd]
	
	# read(3, <read_file>, <read_file_count>) = <read_file_result>
	mov rdi, [rsp]
	mov rsi, offset read_file_buffer
	mov rdx, 1024
	mov rax, 0 # Syscall:read
	syscall
	
	push rax
		#Stack
    # rsp --> [length, open_fd, accept_fd]
	
	# close(3) = 0
	mov rdi, [rsp + 8]
	mov rax, 0x3 # Syscall:close
	syscall
	
	# write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
	mov rdi, [rsp + 16]
	mov rsi, offset response
	mov rdx, 19
	mov rax, 1
	syscall
	
	# write(4, <write_file>, <write_file_count>)=<write_file_result>
	mov rdi, rdi
	mov rsi, offset read_file_buffer
	mov rdx, [rsp]
	mov rax, 1
	syscall
	
	jmp say_bye_bye

deal_with_post:
	# open("<open_path>", O_RDWR) = 3
	mov rdi, offset open_path
	mov rsi, 0x41 # O_WRONLY | O_CREAT
	mov rdx, 0777
	mov rax, 2
	syscall
	
	push rax
	
	#Stack
    # rsp --> [open_fd, accept_fd]
	
	# read(3, <read_file>, <read_file_count>) = <read_file_result>
	mov rdi, [rsp]
	mov rsi, offset read_file_buffer
	mov rdx, 1024
	mov rax, 1 # Syscall:write
	syscall
	
    mov rdi, offset read_file_buffer
    mov rsi, offset content_length
    mov rcx, 14
    
check_every_word:
	cmp rcx, 0
	je get_post_length
    # 一个一个字符检查
    movb al, [rdi]                      ; 读取当前字节
    movb bl, [rsi]                         ; 检查是否是换行符
    cmpb al, bl
    jne new_to_check
    inc rdi
    inc rsi
    sub rcx, 1
    jmp check_every_word

new_to_check:
	inc rdi
	jmp check_every_word
	
say_bye_bye:
	# exit(0) = ?
	mov rdi, 0
	mov rax, 60
	syscall

get_post_length:
	
	
.section .data
    # sockaddr_in 结构体数据
    addr:
        # sin_family = AF_INET (2)
        .2byte 2    
        # sin_port = 80 (0x0050 in hex, 网络字节序)
        .byte 0
        .byte 80
        # sin_addr = 0.0.0.0 (绑定到所有接口)
        .long 0x00000000
        # __pad = 填充字段 (8字节)
        .quad 0
    response:
		.string "HTTP/1.0 200 OK\r\n\r\n"
	get_req:
		.string "GET"
	post_req:
		.string "POST"
	content_length:
		.string "Content-Length: "

.section .bss
	request_buffer: .skip 1024
	open_path: .skip 1024
	read_file_buffer: .skip 1024
```





# GET



```http
GET /tmp/tmpvja60xad HTTP/1.1\r\n
Host: localhost\r\n
User-Agent: python-requests/2.32.3\r\n
Accept-Encoding: gzip, deflate, zstd\r\n
Accept: */*\r\n
Connection: keep-alive\r\n
\r\n
```



# POST

```http
POST /tmp/tmpi5ege3vk HTTP/1.1\r\n
Host: localhost\r\n
User-Agent: python-requests/2.32.3\r\n
Accept-Encoding: gzip, deflate, zstd\r\n
Accept: */*\r\n
Connection: keep-alive\r\n
Content-Length: 245\r\n
\r\n
fo6eACJlqwS5qyIHrt16xpPlKJi5vygaLpfSyDysVQdgzS3XVQnLRoqWPpaboH0rigJYAMCkPGS7PkYmTsqMviILJvOUn93i54A7WpAgzAdJABqcK1hBoRzgOoYbEDy083YZgOmBshL3fXm0iEEPrNcNKgQyxAZr8nrykbDMhpQ9yW5jTMXvYLv17IIy40aXfcALRU3JrnSjnVAMlL4xrN5jhK6mCJyXigu4Srox7tCdm7Anf7wd9
```



