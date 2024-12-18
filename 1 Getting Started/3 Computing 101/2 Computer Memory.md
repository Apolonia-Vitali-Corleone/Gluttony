# 1

```sh
hacker@memory~loading-from-memory:~$ /challenge/
.py/            DESCRIPTION.md  check           
hacker@memory~loading-from-memory:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
mov rdi, [133700]              
This challenge expects 3 instructions, but you provided 1.
hacker@memory~loading-from-memory:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
mov rdi, [133700]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 133700 (value 233) to succeed!

hacker@memory~loading-from-memory:~$ /tmp/your-program
hacker@memory~loading-from-memory:~$ echo $?
233
hacker@memory~loading-from-memory:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{4P-GYEH2FXLgMOn40KyJjLEScMM.QX0ITO1wCO5IzW}

hacker@memory~loading-from-memory:~$ 
```

# 2



```sh
hacker@memory~more-loading-practice:~$ /challenge/c
bash: /challenge/c: No such file or directory
hacker@memory~more-loading-practice:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, [123400]
mov rax, 60
syscall 

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret value
stored at memory address 123400 (value 251) to succeed!

hacker@memory~more-loading-practice:~$ /tmp/your-program
hacker@memory~more-loading-practice:~$ echo $?
251
hacker@memory~more-loading-practice:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{wsFsWIHhJeK5U_NNbyShHYJxdw8.QXwMTO1wCO5IzW}

hacker@memory~more-loading-practice:~$ 
```





# 3

```sh
hacker@memory~dereferencing-pointers:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi,[rax]
mov rax,60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by rax (value 79) to succeed!

hacker@memory~dereferencing-pointers:~$ /tmp/your-program
hacker@memory~dereferencing-pointers:~$ echo $?
79
hacker@memory~dereferencing-pointers:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{AGa4CToVWQpuwqkzAQDI0jmTIyB.QXxMTO1wCO5IzW}

hacker@memory~dereferencing-pointers:~$ 
```



# 4

```assembly
hacker@memory~dereferencing-yourself:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rdi]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by rdi (value 149) to succeed!

hacker@memory~dereferencing-yourself:~$ /tmp/your-program
hacker@memory~dereferencing-yourself:~$ echo $?
149
hacker@memory~dereferencing-yourself:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{MVXrvDFiARXDnVlBCEn6GPjxDij.QXyMTO1wCO5IzW}

hacker@memory~dereferencing-yourself:~$ 
```



# 5

```sh
hacker@memory~dereferencing-with-offsets:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rdi+8]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by rdi (value 219) to succeed!

hacker@memory~dereferencing-with-offsets:~$ /tmp/your-program
hacker@memory~dereferencing-with-offsets:~$ echo $?
219
hacker@memory~dereferencing-with-offsets:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{YFini5FRzKrLOMqi6sdTZY-6fHa.QX1QTO1wCO5IzW}

hacker@memory~dereferencing-with-offsets:~$ 
```



# 6

```sh
hacker@memory~stored-addresses:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, [567800]
mov rdi, [rdi]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by a chain of pointers starting at address 20149769!

hacker@memory~stored-addresses:~$ /tmp/your-program
hacker@memory~stored-addresses:~$ echo $?
105
hacker@memory~stored-addresses:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{AwtFYEy88ZYK2Z1BrjQXF3fKrLV.QXzMTO1wCO5IzW}

hacker@memory~stored-addresses:~$ 
```



# 7

```sh
hacker@memory~double-dereference:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rax, [rax]
mov eax, [rax]

This challenge expects 4 instructions, but you provided 2.
hacker@memory~double-dereference:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rax, [rax]
mov rax, [rax]
mov rdi, rax
mov rax, 60
syscall
This challenge expects 4 instructions, but you provided 5.
hacker@memory~double-dereference:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rax, [rax]
mov rdi, [rax]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by a chain of pointers starting at rax!

hacker@memory~double-dereference:~$ /tmp/your-program
hacker@memory~double-dereference:~$ echo $?
113
hacker@memory~double-dereference:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{Ens7vuZxSNP845tqGPcDgsh0LpT.QX0MTO1wCO5IzW}

hacker@memory~double-dereference:~$ 
```



# 8



```sh
hacker@memory~triple-dereference:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, [rdi]
mov rdi, [rdi]
mov rdi, [rdi]
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value pointed to by a chain of pointers starting at rdi!

hacker@memory~triple-dereference:~$ /tmp/your-program
hacker@memory~triple-dereference:~$ echo $?
73
hacker@memory~triple-dereference:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{46KT8MjCa6PfmvXbm6-e0A8yIEP.QXzQTO1wCO5IzW}

hacker@memory~triple-dereference:~$ 
```



