# 1

```shell
hacker@users~becoming-root-with-su:~$ su
Password: 
root@users~becoming-root-with-su:/home/hacker# cat /flag 
pwn.college{4uHJ2E-Tf142YiaG-ivqI4DDJZM.QX1UDN1wCO5IzW}
root@users~becoming-root-with-su:/home/hacker# ls -l /flag 
-r-------- 1 root root 56 Oct 19 08:10 /flag
root@users~becoming-root-with-su:/home/hacker# 
```





# 2

```sh
hacker@users~other-users-with-su:~$ ls -l /challenge/run 
-rwsr-xr-x 1 root root 262 Jul 17 17:57 /challenge/run
hacker@users~other-users-with-su:~$ /challenge/run 
You are the hacker user... You MUST become the zardus user before executing 
this command.
hacker@users~other-users-with-su:~$ su zardus
Password: 
zardus@users~other-users-with-su:/home/hacker$ ls -l /challenge/run 
-rwsr-xr-x 1 root root 262 Jul 17 17:57 /challenge/run
zardus@users~other-users-with-su:/home/hacker$ /challenge/run 
Congratulations, you have become Zardus! Here is your flag:
pwn.college{wskiWXir_NPSRjEHSec3Hs6L4sM.QX2UDN1wCO5IzW}
zardus@users~other-users-with-su:/home/hacker$ 
```



# 3

```sh
hacker@users~cracking-passwords:~$ ls -al /challenge/
total 28
drwxr-xr-x 1 root root   4096 Oct 19 08:19 .
drwxr-xr-x 1 root root   4096 Oct 19 08:19 ..
-rwsr-xr-- 1 root zardus   35 Jul 17 19:41 .catflag
-rwsr-xr-x 1 root root   3487 Aug 18 06:57 DESCRIPTION.md
drwsr-xr-x 2 root root   4096 Oct 19 08:19 bin
-rwsr-xr-x 1 root root    262 Jul 17 19:41 run
-rw-r--r-- 1 root root    661 Oct 19 08:19 shadow-leak
hacker@users~cracking-passwords:~$ file $(ls /challenge/)
DESCRIPTION.md: cannot open `DESCRIPTION.md' (No such file or directory)
bin:            cannot open `bin' (No such file or directory)
run:            cannot open `run' (No such file or directory)
shadow-leak:    cannot open `shadow-leak' (No such file or directory)
hacker@users~cracking-passwords:~$ ls /challenge/
DESCRIPTION.md  bin  run  shadow-leak
hacker@users~cracking-passwords:~$ file /challenge/shadow-leak 
/challenge/shadow-leak: ASCII text
hacker@users~cracking-passwords:~$ john /challenge/shadow-leak 
Created directory: /home/hacker/.john
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
aardvark         (zardus)
1g 0:00:00:20 100% 2/3 0.04842g/s 281.9p/s 281.9c/s 281.9C/s Johnson..buzz
Use the "--show" option to display all of the cracked passwords reliably
Session completed
hacker@users~cracking-passwords:~$ su zardus
Password: 
zardus@users~cracking-passwords:/home/hacker$ /challenge/run 
Congratulations, you have become Zardus! Here is your flag:
pwn.college{UWveNtk2HVWo8kfxwDxiSTUc4Zv.QX3UDN1wCO5IzW}
zardus@users~cracking-passwords:/home/hacker$ 
```



# 4

```shell
hacker@users~using-sudo:~$ sudo cat /flag 
pwn.college{Akw4nQdeDUy4m7O9pWCXSOlhkc9.QX4UDN1wCO5IzW}
hacker@users~using-sudo:~$ 
```



