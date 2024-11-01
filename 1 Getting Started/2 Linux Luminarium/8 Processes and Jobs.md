# 1-ListingProcesses

```sh
hacker@processes~listing-processes:~$ ls /challenge/
ls: cannot open directory '/challenge/': Permission denied
hacker@processes~listing-processes:~$ ps
    PID TTY          TIME CMD
    186 pts/0    00:00:00 bash
    266 pts/0    00:00:00 ps
hacker@processes~listing-processes:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   1056   640 ?        Ss   14:40   0:00 /sbin/docker-init -- /nix/var/nix/profiles/default/bin/dojo-init /run/dojo/bin/
root           7  0.0  0.0   5052  2240 ?        S    14:40   0:00 /run/dojo/bin/sleep 6h
root          68  0.0  0.0   4132  2560 ?        S    14:40   0:00 /challenge/2525-run-13393
root          72  0.0  0.0   2744  1280 ?        S    14:40   0:00 sleep 6h
hacker        81  2.8  0.0 1100300 64252 ?       Sl   14:40   0:00 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       102 20.0  0.0 1317744 93368 ?       Sl   14:40   0:05 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       138 10.6  0.0 1329772 90920 ?       Sl   14:40   0:02 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node --dns-resul
hacker       169  3.1  0.0 1103660 55636 ?       Rl   14:41   0:00 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       186  0.1  0.0   5372  3840 pts/0    Ss   14:41   0:00 /run/dojo/bin/bash --init-file /nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code
hacker       296  0.0  0.0   7868  3200 pts/0    R+   14:41   0:00 ps aux




hacker@processes~listing-processes:~$ /challenge/2525-run-13393
Yahaha, you found me! Here is your flag:
pwn.college{UZOcjzjiFc_1eWP1KWWri6TsGSo.QX4MDO0wCO5IzW}
Now I will sleep for a while (so that you could find me with 'ps').

```



不过是在教我ps的使用，看进程这些



# 2-kiiing Processes

```sh
hacker@processes~killing-processes:~$ /challenge/run 
Nope! /challenge/dont_run is still running! You gotta terminate it before I 
give you the flag!



hacker@processes~killing-processes:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   1056   640 ?        Ss   14:46   0:00 /sbin/docker-init -- /nix/var/nix/profiles/default/bin/dojo-init /run/dojo/bin/
root           7  0.0  0.0   5052  2240 ?        S    14:46   0:00 /run/dojo/bin/sleep 6h
root          71  0.0  0.0   4732  2880 ?        S    14:46   0:00 su -c /challenge/.launcher hacker
hacker        73  0.0  0.0   4976  3200 ?        Ss   14:46   0:00 /challenge/dont_run
hacker        74  0.0  0.0   5052  2560 ?        S    14:46   0:00 sleep 6h
hacker        83  0.5  0.0 1100056 62632 ?       Sl   14:47   0:00 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       104  4.4  0.0 1356156 130584 ?      Sl   14:47   0:06 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       164 10.9  0.0 1360604 103728 ?      Sl   14:49   0:01 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node --dns-resul
hacker       201  4.0  0.0 1107364 58880 ?       Rl   14:49   0:00 /nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node /nix/store/
hacker       212  0.1  0.0   5372  4160 pts/0    Ss   14:50   0:00 /run/dojo/bin/bash --init-file /nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code
hacker       289  0.0  0.0   7868  3520 pts/0    R+   14:50   0:00 ps aux


hacker@processes~killing-processes:~$ kill 73


hacker@processes~killing-processes:~$ /challenge/run 
Great job! Here is your payment:
pwn.college{QIqx0Zi65k-UJsf9GiCFZX54U8U.QXyQDO0wCO5IzW}
hacker@processes~killing-processes:~$ 
```





# 3-Interrupting Processes

```sh
hacker@processes~interrupting-processes:~$ /challenge/run 
I could give you the flag... but I won't, until this process exits. Remember, 
you can force me to exit with Ctrl-C. Try it now!
^C
Good job! You have used Ctrl-C to interrupt this process! Here is your flag:
pwn.college{IVCSk7AI-f37uFZxYh4X-8SWJc9.QXzQDO0wCO5IzW}
```



# 4-suspending Processes

```sh
hacker@processes~suspending-processes:~$ /challenge/run 
I'll only give you the flag if there's already another copy of me running in 
this terminal... Let's check!

UID          PID    PPID  C STIME TTY          TIME CMD
root         243     178  0 14:54 pts/0    00:00:00 bash /challenge/run
root         245     243  0 14:54 pts/0    00:00:00 ps -f

I don't see a second me!

To pass this level, you need to suspend me and launch me again! You can 
background me with Ctrl-Z or, if you're not ready to do that for whatever 
reason, just hit Enter and I'll exit!
^Z
[1]+  Stopped                 /challenge/run




hacker@processes~suspending-processes:~$ /challenge/run 
I'll only give you the flag if there's already another copy of me running in 
this terminal... Let's check!

UID          PID    PPID  C STIME TTY          TIME CMD
root         243     178  0 14:54 pts/0    00:00:00 bash /challenge/run
root         327     178  0 14:54 pts/0    00:00:00 bash /challenge/run
root         329     327  0 14:54 pts/0    00:00:00 ps -f

Yay, I found another version of me! Here is the flag:
pwn.college{c9V_PZjOn34wTyAXa-Jl3OkV1Np.QX1QDO0wCO5IzW}
```



# 5-Resuming Processes

```sh
hacker@processes~resuming-processes:~$ /challenge/run 
Let's practice resuming processes! Suspend me with Ctrl-Z, then resume me with 
the 'fg' command! Or just press Enter to quit me!
^Z
[1]+  Stopped                 /challenge/run




hacker@processes~resuming-processes:~$ fg
/challenge/run
I'm back! Here's your flag:
pwn.college{8Rq7SHOx23ImFmQqw5H94xeXGAh.QX2QDO0wCO5IzW}
Don't forget to press Enter to quit me!

Goodbye!



hacker@processes~resuming-processes:~$ /challenge/run 
Let's practice resuming processes! Suspend me with Ctrl-Z, then resume me with 
the 'fg' command! Or just press Enter to quit me!

Goodbye!
```



# 6-Backgrounding Processes

```shell
hacker@processes~backgrounding-processes:~$ /challenge/run 
I'll only give you the flag if there's already another copy of me running *and 
not suspended* in this terminal... Let's check!

UID          PID STAT CMD
root        1002 S+   bash /challenge/run
root        1004 R+   ps -o user=UID,pid,stat,cmd

I don't see a second me!

To pass this level, you need to suspend me, resume the suspended process in the 
background, and then launch a new version of me! You can background me with 
Ctrl-Z (and resume me in the background with 'bg') or, if you're not ready to 
do that for whatever reason, just hit Enter and I'll exit!
^Z
[1]+  Stopped                 /challenge/run



hacker@processes~backgrounding-processes:~$ bg
[1]+ /challenge/run &



Yay, I'm now running the background! Because of that, this text will probably 
overlap weirdly with the shell prompt. Don't panic; just hit Enter a few times 
to scroll this text out.



hacker@processes~backgrounding-processes:~$ /challenge/run 
I'll only give you the flag if there's already another copy of me running *and 
not suspended* in this terminal... Let's check!

UID          PID STAT CMD
root        1002 S    bash /challenge/run
root        1086 S    sleep 6h
root        1128 S+   bash /challenge/run
root        1130 R+   ps -o user=UID,pid,stat,cmd

Yay, I found another version of me running in the background! Here is the flag:
pwn.college{wFDr9geWUmgGge7MC5ZpHZW5Wki.QX3QDO0wCO5IzW}
```





# 7-Foregrounding Processes

```shell
hacker@processes~foregrounding-processes:~$ /challenge/run 
To pass this level, you need to suspend me, resume the suspended process in the 
background, and *then* foreground it without re-suspending it! You can 
background me with Ctrl-Z (and resume me in the background with 'bg') or, if 
you're not ready to do that for whatever reason, just hit Enter and I'll exit!
^Z
[1]+  Stopped                 /challenge/run



hacker@processes~foregrounding-processes:~$ bg
[1]+ /challenge/run &



Yay, I'm now running the background! Because of that, this text will probably 
overlap weirdly with the shell prompt. Don't panic; just hit Enter a few times 
to scroll this text out. After that, resume me into the foreground with 'fg'; 
I'll wait.
hacker@processes~foregrounding-processes:~$ fg
/challenge/run
YES! Great job! I'm now running in the foreground. Hit Enter for your flag!

pwn.college{w3S2Ohf-gvKOh9CLfE4I_ADC0F2.QX4QDO0wCO5IzW}

```

好奇怪



# 8-starting Backgrounded Processes



```shell
hacker@processes~starting-backgrounded-processes:~$ /challenge/run &
[1] 357



Yay, you started me in the background! Because of that, this text will probably 
overlap weirdly with the shell prompt, but you're used to that by now...

Anyways! Here is your flag!
pwn.college{8Ed7IwSI5pUOWw7aEIML11NFqBA.QX5QDO0wCO5IzW}
[1]+  Done                    /challenge/run
```



# 9-Process Exit codes



```shell
hacker@processes~process-exit-codes:~$ /challenge/get-code 
Exiting with an error code!



hacker@processes~process-exit-codes:~$ echo $?
198



hacker@processes~process-exit-codes:~$ /challenge/submit-code 
You must run /challenge/submit-code with the exit code you retrieved from 
/challenge/get-code as the first argument:

Usage: /challenge/submit-code [EXIT_CODE]




hacker@processes~process-exit-codes:~$ /challenge/submit-code  198
CORRECT! Here is your flag:
pwn.college{8hD7RBGrbnAkz1PdwbYX26rdYxU.QX5YDO1wCO5IzW}
```

