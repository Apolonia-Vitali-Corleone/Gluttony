# 1-chaining-with-semicolons

用分号连续执行指令

```
hacker@chaining~chaining-with-semicolons:~$ /challenge/pwn ; /challenge/college 
Yes! You chained /challenge/pwn and /challenge/college! Here is your flag:
pwn.college{QSo979QobAicEIOmpH657lSrk5o.QX1UDO0wCO5IzW}
hacker@chaining~chaining-with-semicolons:~$ 
```



# 2-your-first-shell-script

用bash执行.sh文件

```sh
hacker@chaining~your-first-shell-script:~$ ls
flag  lost+found  past
hacker@chaining~your-first-shell-script:~$ vim x.sh
hacker@chaining~your-first-shell-script:~$ cat x.sh 
/challenge/pwn ; /challenge/college
hacker@chaining~your-first-shell-script:~$ bash x.sh 
Great job, you've written your first shell script! Here is the flag:
pwn.college{cwK8XRDpU9X3TnOcKth4OSdcFrG.QXxcDO0wCO5IzW}
hacker@chaining~your-first-shell-script:~$ 
```



# 3-redirecting-script-output

```bash
hacker@chaining~redirecting-script-output:~$ bash x.sh | /challenge/solve 
Correct! Here is your flag:
pwn.college{E-0z5x-exjGV3pohnk-7UlBBTOu.QX4ETO0wCO5IzW}
hacker@chaining~redirecting-script-output:~$ 
```

使用bash执行.sh文件



# 4-executable-shell-scripts

```shell
hacker@chaining~executable-shell-scripts:~$ vim ./x.sh 
hacker@chaining~executable-shell-scripts:~$ cat ./x.sh 
/challenge/solve
hacker@chaining~executable-shell-scripts:~$ chmod 777 ./x.sh 
hacker@chaining~executable-shell-scripts:~$ ./x.sh 
Congratulations on your shell script execution! Your flag:
pwn.college{gXuTE4y2HdK52-0JaEtXLrc84ct.QX0cjM1wCO5IzW}
hacker@chaining~executable-shell-scripts:~$ 
```

直接执行.sh文件

