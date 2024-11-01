# 1

```sh
hacker@hello-hackers~writing-output:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, 1
mov rsi, [1337000]
mov rdx, 10
mov rax, 1
syscall

Checking the assembly code...
... oops, we found an issue! Details below:

You must properly set register rsi to the value 1337000 (the address where the secret value is stored)!
hacker@hello-hackers~writing-output:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, 1
mov rsi, 1337000
mov rdx, 10
mov rax, 1
syscall

Checking the assembly code...
... oops, we found an issue! Details below:

You must properly set register rdx to the value 1 (just write a single byte)!
hacker@hello-hackers~writing-output:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, 1
mov rsi, 1337000
mov rdx, 1
mov rax, 1
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 1337000 (the letter H) to succeed!

hacker@hello-hackers~writing-output:~$ /tmp/your-program
HSegmentation fault (core dumped)
hacker@hello-hackers~writing-output:~$ 


Wow, you wrote an "H"!!!!!!! But why did your program crash? Well, you didn't
exit, and as before, the CPU kept executing and eventually crashed. In the next
level, we will learn how to chain two system calls togeter: write and exit!


Here is your flag!
pwn.college{AVC1rnNISpQqDe0vBulv3_M8B_R.QXwUTN2wCO5IzW}

hacker@hello-hackers~writing-output:~$ 
```

妈的无语



# 2

```sh
hacker@hello-hackers~chaining-syscalls:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, 1
mov rsi, 1337000
mov rdx, 1
mov rax, 1
syscall
mov rdi, 42
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 1337000 (the letter H) to succeed!

hacker@hello-hackers~chaining-syscalls:~$ /tmp/your-program
Hhacker@hello-hackers~chaining-syscalls:~$ 

YES! You wrote an 'H' and cleanly exited! Great job!

Here is your flag!
pwn.college{EQ004KSZh4gzFKeQNmpgAzjUW36.QXxUTN2wCO5IzW}

hacker@hello-hackers~chaining-syscalls:~$ 
```



# 3

```
.intel_syntax noprefix
.global _start
_start:
mov rdi, 1
mov rsi, 1337000
mov rdx, 0xe
mov rax, 1
syscall
mov rdi, 42
mov rax, 60
syscall
```



```sh
hacker@hello-hackers~writing-strings:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix                                                                                                           
.global _start
_start:
mov rdi, 1
mov rsi, 1337000
mov rdx, 0xe
mov rax, 1
syscall
mov rdi, 42
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 1337000 (the string "Hello Hackers!" ) to succeed!

hacker@hello-hackers~writing-strings:~$ /tmp/your-program
Hello Hackers!hacker@hello-hackers~writing-strings:~$ 

YES! You wrote a "Hello Hackers" and cleanly exited! Great job!

Here is your flag!
pwn.college{QcndATOLw2GUoWwE257hQtilkVC.01NzEDMxwCO5IzW}

hacker@hello-hackers~writing-strings:~$ 
```

