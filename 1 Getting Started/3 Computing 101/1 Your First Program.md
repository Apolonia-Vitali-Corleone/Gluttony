# 1

```
mov rax, 60
```



# 2

```sh
hacker@your-first-program~your-first-syscall:~$ /challenge/
.py/            DESCRIPTION.md  check           
hacker@your-first-program~your-first-syscall:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Okay, now you have written your first COMPLETE program!
All it'll do is exit, but it'll do so cleanly, and we can
build from there!

Let's see what happens when you run it:

hacker@your-first-program~your-first-syscall:~$ /tmp/your-program
hacker@your-first-program~your-first-syscall:~$ 

Neat! Your program exited cleanly! Let's push on to make things
more interesting! Take this with you:


Here is your flag!
pwn.college{81krzRNHz1iVS6owS3hgom_L61l.QX4YDO1wCO5IzW}

hacker@your-first-program~your-first-syscall:~$ 
```



# 3

```sh
hacker@your-first-program~exit-codes:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
mov rdi, 42
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be 42 to succeed!

Go go go!

hacker@your-first-program~exit-codes:~$ /tmp/your-program
hacker@your-first-program~exit-codes:~$ echo $?
42
hacker@your-first-program~exit-codes:~$ 

Neat! Your program exited with the correct error code! But in this level,
we built the executable for you. Next, you'll learn how to build the executable
yourself, and then you'll be ready to walk the path of Assembly!

For now, take this with you:



Here is your flag!
pwn.college{omq_ys-ec3Upa5HrA5pSx7ipapM.QXwcDO1wCO5IzW}

hacker@your-first-program~exit-codes:~$ 
```



# 4

```sh
hacker@your-first-program~building-executables:~$ /challenge/
.py/            DESCRIPTION.md  check           
hacker@your-first-program~building-executables:~$ /challenge/check 
Please run this program as `/challenge/check your-program.elf`!
hacker@your-first-program~building-executables:~$ touch exe.s
hacker@your-first-program~building-executables:~$ vim exe.s 
hacker@your-first-program~building-executables:~$ mov ./exe.s ./elf.s
bash: mov: command not found
hacker@your-first-program~building-executables:~$ mv ./exe.s ./elf.s
hacker@your-first-program~building-executables:~$ ls
111  222  998  core  elf.s  foriso  lost+found  my_command  past  x.sh
hacker@your-first-program~building-executables:~$ as -o elf.o ./elf.s 
hacker@your-first-program~building-executables:~$ ld -o elf ./elf.o
hacker@your-first-program~building-executables:~$ /challenge/check ./elf

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be 42 to succeed!

Go go go!

hacker@your-first-program~building-executables:~$ /tmp/your-program
hacker@your-first-program~building-executables:~$ echo $?
42
hacker@your-first-program~building-executables:~$ 

Neat! Your program exited with the correct error code! But what
if it hadn't? Next, we'll learn about some simple debugging.
For now, take this with you:



Here is your flag!
pwn.college{gs7-s17YM-AuAkGckY0CROR11JU.0FM3IDMxwCO5IzW}

hacker@your-first-program~building-executables:~$ cat ./elf.s
.intel_syntax noprefix
.global _start
_start:
mov rdi, 42
mov rax, 60
syscall
hacker@your-first-program~building-executables:~$ 
```



# 5

```
hacker@your-first-program~tracing-syscalls:~$ strace /challenge/trace-me 
execve("/challenge/trace-me", ["/challenge/trace-me"], 0x7fff8e456f30 /* 23 vars */) = 0
alarm(26072)                            = 0
exit(0)                                 = ?
+++ exited with 0 +++
hacker@your-first-program~tracing-syscalls:~$ /challenge/submit-number 26072
CORRECT! Here is your flag:
pwn.college{I2Rq3evLYZiqTsXjA8RaVumP-9_.QXxcDO1wCO5IzW}
hacker@your-first-program~tracing-syscalls:~$ 
```



# 6

```sh
hacker@your-first-program~moving-between-registers:~$ /challenge/
.py/            DESCRIPTION.md  check           
hacker@your-first-program~moving-between-registers:~$ /challenge/check 
Please input your assembly. Press Ctrl+D when done!
.intel_syntax noprefix
.global _start
_start:
mov rdi, rsi
mov rax, 60
syscall

Checking the assembly code...
... YES! Great job!

Let's check what your exit code is! It should be our secret
value stored in register rsi (value 54) to succeed!

hacker@your-first-program~moving-between-registers:~$ /tmp/your-program
hacker@your-first-program~moving-between-registers:~$ echo $?
54
hacker@your-first-program~moving-between-registers:~$ 

Neat! Your program passed the tests! Great job!

Here is your flag!
pwn.college{MP_-wBpdduVEiVCTI7P_ReCl7XL.QX5QTN2wCO5IzW}

hacker@your-first-program~moving-between-registers:~$ 
```



