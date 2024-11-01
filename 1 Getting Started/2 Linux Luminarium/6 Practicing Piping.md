# 1-Redirecting output

```bash
hacker@piping~redirecting-output:~$ echo PWN > COLLEGE
Correct! You successfully redirected 'PWN' to the file 'COLLEGE'! Here is your 
flag:
pwn.college{s3aB3BGG7aB2jlcSwb0OTRqf8yu.QX0YTN0wCO5IzW}

# 等同于

hacker@piping~redirecting-output:~$ echo PWN 1> COLLEGE
Correct! You successfully redirected 'PWN' to the file 'COLLEGE'! Here is your 
flag:
pwn.college{s3aB3BGG7aB2jlcSwb0OTRqf8yu.QX0YTN0wCO5IzW}
hacker@piping~redirecting-output:~$ 
```



# 2-Redirecting more output

```shell
hacker@piping~redirecting-more-output:~$ /challenge/run 
[INFO] WELCOME! This challenge makes the following asks of you:
[INFO] - the challenge will check that output is redirected to a specific file path : myflag
[INFO] - the challenge will output a reward file if all the tests pass : /flag

[HYPE] ONWARDS TO GREATNESS!

[INFO] This challenge will perform a bunch of checks.
[INFO] If you pass these checks, you will receive the /flag file.

[TEST] You should have redirected my stdout to a file called myflag. Checking...

[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]   You have not redirected anything for this process' stdout.



hacker@piping~redirecting-more-output:~$ /challenge/run > myflag
[INFO] WELCOME! This challenge makes the following asks of you:
[INFO] - the challenge will check that output is redirected to a specific file path : myflag
[INFO] - the challenge will output a reward file if all the tests pass : /flag

[HYPE] ONWARDS TO GREATNESS!

[INFO] This challenge will perform a bunch of checks.
[INFO] If you pass these checks, you will receive the /flag file.

[TEST] You should have redirected my stdout to a file called myflag. Checking...

[PASS] The file at the other end of my stdout looks okay!
[PASS] Success! You have satisfied all execution requirements.


hacker@piping~redirecting-more-output:~$ cat myflag

[FLAG] Here is your flag:
[FLAG] pwn.college{E0ksN7vqvfm_4v_3PN24S04HI9G.QX1YTN0wCO5IzW}

hacker@piping~redirecting-more-output:~$ 
```



# 3-Appending output



```sh
hacker@piping~appending-output:~$ /challenge/run > /home/hacker/the-flag

hacker@piping~appending-output:~$ /challenge/run >> /home/hacker/the-flag


hacker@piping~appending-output:~$ cat ./the-flag 
 | 
\|/ This is the first half:
 v 
pwn.college{sgOD5A3MXOO6QcJJiVh3EOxhOQq.QX3ATO0wCO5IzW}
                              ^
     that is the second half /|\
                              |


```



# 4-Redirecting errors

```shell
hacker@piping~redirecting-errors:~$ /challenge/run > myflag 2> instructions

# flag就在myflag
hacker@piping~redirecting-errors:~$ cat myflag 

[FLAG] Here is your flag:
[FLAG] pwn.college{gAqgpdx49rd4kMA2RgVKktIdhoy.QX3YTN0wCO5IzW}

# 看看instructions
hacker@piping~redirecting-errors:~$ cat instructions 
[INFO] WELCOME! This challenge makes the following asks of you:
[INFO] - the challenge will check that output is redirected to a specific file path : myflag
[INFO] - the challenge will check that error output is redirected to a specific file path : instructions
[INFO] - the challenge will output a reward file if all the tests pass : /flag

[HYPE] ONWARDS TO GREATNESS!

[INFO] This challenge will perform a bunch of checks.
[INFO] If you pass these checks, you will receive the /flag file.

[TEST] You should have redirected my stdout to a file called myflag. Checking...

[PASS] The file at the other end of my stdout looks okay!

[TEST] You should have redirected my stderr to instructions. Checking...

[PASS] The file at the other end of my stderr looks okay!
[PASS] Success! You have satisfied all execution requirements.

```







# 5-Redirecting input

```
hacker@piping~redirecting-input:~$ /challenge/run <0  $(echo COLLEGE 1> PWN)
bash: 0: No such file or directory
hacker@piping~redirecting-input:~$ /challenge/run < $(echo COLLEGE 1> PWN)
bash: $(echo COLLEGE > PWN): ambiguous redirect
hacker@piping~redirecting-input:~$ echo COLLEGE 1> PWN
hacker@piping~redirecting-input:~$ /challenge/run <0 PWN 
bash: 0: No such file or directory
hacker@piping~redirecting-input:~$ /challenge/run <0  
bash: 0: No such file or directory
hacker@piping~redirecting-input:~$ /challenge/run < PWN  
Reading from standard input...
Correct! You have redirected the PWN file into my standard input, and I read 
the value 'COLLEGE' out of it!
Here is your flag:
pwn.college{wNfhReuDo5D0gOoYcvavxyhSEAT.QXwcTN0wCO5IzW}
hacker@piping~redirecting-input:~$ 

```

也许我只是在钻牛角尖？

Redirect的>本身就是对stream中的0和1和2操作的

但是<就是取代的0，你不能   <0   

哈哈哈哈哈哈

# 6-Grepping stored results

```
hacker@piping~grepping-stored-results:~$ /challenge/run > /tmp/data.txt
[INFO] WELCOME! This challenge makes the following asks of you:
[INFO] - the challenge will check that output is redirected to a specific file path : /tmp/data.txt
[INFO] - the challenge will output a reward file if all the tests pass : /challenge/.data.txt

[HYPE] ONWARDS TO GREATNESS!

[INFO] This challenge will perform a bunch of checks.
[INFO] If you pass these checks, you will receive the /challenge/.data.txt file.

[TEST] You should have redirected my stdout to a file called /tmp/data.txt. Checking...

[HINT] File descriptors are inherited from the parent, unless the FD_CLOEXEC is set by the parent on the file descriptor.
[HINT] For security reasons, some programs, such as python, do this by default in certain cases. Be careful if you are
[HINT] creating and trying to pass in FDs in python.

[PASS] The file at the other end of my stdout looks okay!
[PASS] Success! You have satisfied all execution requirements.
hacker@piping~grepping-stored-results:~$ grep flag /tmp/data.txt
[FLAG] Here is your flag:
unflagging
conflagration's
flagship's
camouflage
flagellation
flagellated
flagon's
flagellums
flagging
conflagrations
flagstone's
flagellum
camouflages
flagellate
persiflage
flagellates
flagpole
flagstaff
flagstone
flagon
flagrantly
flagpoles
flag
flagons
flagships
flagella
camouflaging
flagged
flagship
flagpole's
camouflaged
camouflage's
flagrant
flagellation's
conflagration
flagstaffs
persiflage's
flagstaff's
flags
flagellum's
flag's
flagellating
flagstones
hacker@piping~grepping-stored-results:~$ grep pwn.college  /tmp/data.txt
pwn.college{w-1cfkgp1f-yr2OS7SP8rzktJJb.QX4EDO0wCO5IzW}
hacker@piping~grepping-stored-results:~$ 

```

# 7-Grepping live output

```
hacker@piping~grepping-live-output:~$ /challenge/run | grep pwn.college
[INFO] WELCOME! This challenge makes the following asks of you:
[INFO] - the challenge checks for a specific process at the other end of stdout : grep
[INFO] - the challenge will output a reward file if all the tests pass : /challenge/.data.txt

[HYPE] ONWARDS TO GREATNESS!

[INFO] This challenge will perform a bunch of checks.
[INFO] If you pass these checks, you will receive the /challenge/.data.txt file.

[TEST] You should have redirected my stdout to another process. Checking...
[TEST] Performing checks on that process!

[INFO] The process' executable is /nix/store/xpq4yhadyhazkcsggmqd7rsgvxb3kjy4-gnugrep-3.11/bin/grep.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be grep.

[PASS] You have passed the checks on the process on the other end of my stdout!
[PASS] Success! You have satisfied all execution requirements.
pwn.college{IVkceroh--yPCjvmsG-8dOuYq5W.QX5EDO0wCO5IzW}
hacker@piping~grepping-live-output:~$ 

```



# 8.Grepping Errors

```sh
hacker@piping~grepping-errors:~$ /challenge/run 2>&1 | grep pwn.college

pwn.college{8pC9NzQgYl-ioP8B1MkL7idpml1.QX1ATO0wCO5IzW}

```

为什么呢？

因为管道 `|` 是用于**将一个命令的输出传递给另一个命令**作为输入的工具，而文件本身不是一个进程的输出。

`|`这玩意儿本身就是    `1|`，不存在`2|`什么的，就这一个







# 9-Duplicating piped data with tee

我觉得只是单纯教我如何使用tee

```sh
第一步
$ /challenge/pwn | /challenge/college 
Processing...
The input to 'college' does not contain the correct secret code! This code 
should be provided by the 'pwn' command. HINT: use 'tee' to intercept the 
output of 'pwn' and figure out what the code needs to be.

第二步
$ /challenge/pwn | tee problem | /challenge/college 
Processing...
The input to 'college' does not contain the correct secret code! This code 
should be provided by the 'pwn' command. HINT: use 'tee' to intercept the 
output of 'pwn' and figure out what the code needs to be.


第三步
$ cat problem 
Usage: /challenge/pwn --secret [SECRET_ARG]

SECRET_ARG should be "syX-uArU"

第四步
$ /challenge/pwn --secret syX-uArU | /challenge/college 
Processing...
Correct! Passing secret value to /challenge/college...
Great job! Here is your flag:
pwn.college{syX-uArUcKPNbX_hSlhfgbIJ5W7.QXxITO0wCO5IzW}
hacker@piping~duplicating-piped-data-with-tee:~$ 
```

# 10-Writing to multiple programs

困死了，这是chatgpt给我的答案：

```sh
$ /challenge/hack | tee >(/challenge/the) >(/challenge/planet)
This secret data must directly and simultaneously make it to /challenge/the and 
/challenge/planet. Don't try to copy-paste it; it changes too fast.
2281918037236047
Congratulations, you have duplicated data into the input of two programs! Here 
is your flag:
pwn.college{0zKOpYuY6EI5o7nfdLGaYiNMk65.QXwgDN1wCO5IzW}
hacker@piping~writing-to-multiple-programs:~$ 
```

特别好使

有待研究研究

`>(/challenge/the)`，进程替代



# 11-split-piping stderr and stdout

我简直要疯掉

我真不知道怎么做

我草你妈的老子搞出来啦！

真给老子搞恶心了

你重定向到程序，那程序必然是运行着的吧

## answer1

最简单的就是：

```sh

#这个第一次报错，说是语法错好像
$ /challenge/hack >>(/challenge/planet) 2>>(/challenge/the)

shell脚本写规范点，否则会出一些问题

$ /challenge/hack 1> >(/challenge/planet) 2> >(/challenge/the)
Congratulations, you have learned a redirection technique that even experts 
struggle with! Here is your flag:
pwn.college{g8ZmHu-QSGZ3iTPhS3eX1qH2yU3.QXxQDM2wCO5IzW}

```

这是gpt的解释：

```
重要点
同时重定向：两个重定向是同时进行的，hack 的标准输出会流向 planet，而标准错误会流向 the。这两个命令（planet 和 the）分别在不同的进程中运行。
非阻塞执行：由于 Bash 是异步处理的，这两个重定向的命令可以并行运行。即使 hack 还在执行，它的输出和错误已经可以开始流向 planet 和 the。
总结
整个过程是：

/challenge/hack 被启动。
hack 的标准输出被重定向到一个新进程 /challenge/planet。
hack 的标准错误被重定向到另一个新进程 /challenge/the。
这使得 hack 的输出和错误能够被不同的命令独立处理。
```

the和planet是两个子进程

## answer2

第二种写法

```sh
$ /challenge/hack 2> >(/challenge/the) | /challenge/planet 
Congratulations, you have learned a redirection technique that even experts 
struggle with! Here is your flag:
pwn.college{g8ZmHu-QSGZ3iTPhS3eX1qH2yU3.QXxQDM2wCO5IzW}

你注意，你使用  |   之后，后面的重定向就是对/challenge/planet的2的重定向了
注意这个顺序问题

$ /challenge/hack | /challenge/planet 2> >(/challenge/the)
You must redirect my standard error into '/challenge/the'!
You are redirecting standard error *of /challenge/planet*! Instead, you must 
redirect standard error of 'hack'. This must be done *before* any |. The right 
side of the pipe is a different command, with its own redirection, than the 
left side!
Are you sure you're properly redirecting /challenge/hack's standard error into 
'/challenge/the'?

```

