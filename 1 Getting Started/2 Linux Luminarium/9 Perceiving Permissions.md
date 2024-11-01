# 1-Changing File Ownership



```sh
hacker@permissions~changing-file-ownership:~$ /challenge/run 
I have given you access to use the 'chown' command. Use it to enable the flag 
to be read!
hacker@permissions~changing-file-ownership:~$ ls -al /flag 
-r-------- 1 root root 56 Oct 18 16:40 /flag
hacker@permissions~changing-file-ownership:~$ chown hacker /flag 
hacker@permissions~changing-file-ownership:~$ ls -al /flag 
-r-------- 1 hacker root 56 Oct 18 16:40 /flag
hacker@permissions~changing-file-ownership:~$ cat /flag 
pwn.college{wKoeSgu4RAIAtcrPrrXvT7yo7Mx.QXxEjN0wCO5IzW}
hacker@permissions~changing-file-ownership:~$ 
```



# 2-Groups and Files

```sh
hacker@permissions~groups-and-files:~$ /challenge/run 
I have given you access to use the 'chgrp' command. Use it to enable the flag 
to be read!

hacker@permissions~groups-and-files:~$ ls -al /flag
-r--r----- 1 root root 56 Oct 18 16:37 /flag

hacker@permissions~groups-and-files:~$ chgrp hacker /flag

hacker@permissions~groups-and-files:~$ ls -al /flag
-r--r----- 1 root hacker 56 Oct 18 16:37 /flag

hacker@permissions~groups-and-files:~$ cat /flag 
pwn.college{scEzvpaDY5u1pacgLL8xhEzbVs6.QXxcjM1wCO5IzW}

hacker@permissions~groups-and-files:~$ 
```



# 3-Fun with Groups Names

```sh
hacker@permissions~fun-with-groups-names:~$ /challenge/run 
I have given you access to use the 'chgrp' command. Use it to enable the flag 
to be read, but first use 'id' to figure out the group name!

hacker@permissions~fun-with-groups-names:~$ ls -al /flag 
-r--r----- 1 root root 56 Oct 18 16:43 /flag

hacker@permissions~fun-with-groups-names:~$ whoami
hacker

hacker@permissions~fun-with-groups-names:~$ ls -al /usr/bin/chgrp
-rwsr-xr-x 1 root root 72024 Sep  5  2019 /usr/bin/chgrp

hacker@permissions~fun-with-groups-names:~$ id
uid=1000(hacker) gid=1000(grp21046) groups=1000(grp21046)

hacker@permissions~fun-with-groups-names:~$ chgrp grp21046 /flag 

hacker@permissions~fun-with-groups-names:~$ ls -al /usr/bin/chgrp
-rwsr-xr-x 1 root root 72024 Sep  5  2019 /usr/bin/chgrp

hacker@permissions~fun-with-groups-names:~$ ls -al /flag 
-r--r----- 1 root grp21046 56 Oct 18 16:43 /flag

hacker@permissions~fun-with-groups-names:~$ cat /flag
pwn.college{cXt94dJroCXYGZkYeokT2Ac4iLO.QXycjM1wCO5IzW}
hacker@permissions~fun-with-groups-names:~$ 
```



# 4-Changing Permissions

```sh
hacker@permissions~changing-permissions:~$ ls -l /flag 
-r-------- 1 root root 56 Oct 19 08:06 /flag
hacker@permissions~changing-permissions:~$ chmod o+r /flag 
hacker@permissions~changing-permissions:~$ cat /flag 
pwn.college{cY1JZc4SosJC1gs5cnL8X2RaPHs.QXzcjM1wCO5IzW}
hacker@permissions~changing-permissions:~$ 
```



# 5-Executable Files



```sh
hacker@permissions~executable-files:~$ ls -l /challenge/run 
-r--r--r-- 1 hacker hacker 32 Jul  4 06:37 /challenge/run
hacker@permissions~executable-files:~$ chmod u+x /challenge/run 
hacker@permissions~executable-files:~$ /challenge/run 
Successful execution! Here is your flag:
pwn.college{w5TeBJPTi-Xt-E8TnSc2_VQ5F4X.QXyEjN0wCO5IzW}
hacker@permissions~executable-files:~$ 
```



# 6-Permission Tweaking Practice

```sh
hacker@permissions~permission-tweaking-practice:~$ /challenge/run 
Round 0 (of 8)!

Current permissions of "/challenge/pwn": rw-r--r--
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": ------r--
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod ug-rwx /challenge/pwn 
You set the correct permissions!
Round 1 (of 8)!

Current permissions of "/challenge/pwn": ------r--
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": ------rw-
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
* the world does have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod o+w /challenge/pwn 
You set the correct permissions!
Round 2 (of 8)!

Current permissions of "/challenge/pwn": ------rw-
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
* the world does have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": ---------
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod o-rw /challenge/pwn 
You set the correct permissions!
Round 3 (of 8)!

Current permissions of "/challenge/pwn": ---------
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": rw-rw----
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod ug+rw /challenge/pwn 
You set the correct permissions!
Round 4 (of 8)!

Current permissions of "/challenge/pwn": rw-rw----
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": rwxrw----
* the user does have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod u+x /challenge/pwn 
You set the correct permissions!
Round 5 (of 8)!

Current permissions of "/challenge/pwn": rwxrw----
* the user does have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": rw-rw----
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod u-x /challenge/pwn 
You set the correct permissions!
Round 6 (of 8)!

Current permissions of "/challenge/pwn": rw-rw----
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": rwxrw-rwx
* the user does have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
* the world does have write permissions
* the world does have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod uo+rwx /challenge/pwn 
You set the correct permissions!
Round 7 (of 8)!

Current permissions of "/challenge/pwn": rwxrw-rwx
* the user does have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
* the world does have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": ---rw----
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod uo-rwx /challenge/pwn 
You set the correct permissions!
You've solved all 8 rounds! I have changed the ownership
of the /flag file so that you can 'chmod' it. You won't be able to read
it until you make it readable with chmod!

Current permissions of "/flag": ---------
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permission-tweaking-practice:~$ chmod o+r /flag 
hacker@permissions~permission-tweaking-practice:~$ ls -l /flag 
-------r-- 1 hacker hacker 56 Oct 19 05:08 /flag
hacker@permissions~permission-tweaking-practice:~$ chmod u+r /flag 
hacker@permissions~permission-tweaking-practice:~$ cat /flag
pwn.college{0tSj6uByCvSNMWbOrOlB7s9mjc3.QXwEjN0wCO5IzW}
hacker@permissions~permission-tweaking-practice:~$ 
```



# 7-Permissions Setting Practice



```shell
hacker@permissions~permissions-setting-practice:~$ /challenge/run 
Round 0 (of 8)!

Current permissions of "/challenge/pwn": rw-r--r--
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": --xrwx--x
- the user doesn't have read permissions
- the user doesn't have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=x,g=rwx,o=x /challenge/pwn 
You set the correct permissions!
Round 1 (of 8)!

Current permissions of "/challenge/pwn": --xrwx--x
- the user doesn't have read permissions
- the user doesn't have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": -wxrwx---
- the user doesn't have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=wx,g=rwx,o=- /challenge/pwn 
You set the correct permissions!
Round 2 (of 8)!

Current permissions of "/challenge/pwn": -wxrwx---
- the user doesn't have read permissions
* the user does have write permissions
* the user does have execute permissions
* the group does have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": ----wx-wx
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
* the world does have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=-,g=wx,o=wx /challenge/pwn 
You set the correct permissions!
Round 3 (of 8)!

Current permissions of "/challenge/pwn": ----wx-wx
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
* the group does have write permissions
* the group does have execute permissions
- the world doesn't have read permissions
* the world does have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": r--r----x
* the user does have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=r,g=r,o=x /challenge/pwn 
You set the correct permissions!
Round 4 (of 8)!

Current permissions of "/challenge/pwn": r--r----x
* the user does have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": --x--xr--
- the user doesn't have read permissions
- the user doesn't have write permissions
* the user does have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
* the group does have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=x,g=x,o=r /challenge/pwn 
You set the correct permissions!
Round 5 (of 8)!

Current permissions of "/challenge/pwn": --x--xr--
- the user doesn't have read permissions
- the user doesn't have write permissions
* the user does have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
* the group does have execute permissions
* the world does have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions

Needed permissions of "/challenge/pwn": ---r-xrwx
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
* the group does have execute permissions
* the world does have read permissions
* the world does have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=-,g=rx,o=rwx /challenge/pwn 
You set the correct permissions!
Round 6 (of 8)!

Current permissions of "/challenge/pwn": ---r-xrwx
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
* the group does have execute permissions
* the world does have read permissions
* the world does have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": -wx-w--wx
- the user doesn't have read permissions
* the user does have write permissions
* the user does have execute permissions
- the group doesn't have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
* the world does have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=wx,g=w,o=wx /challenge/pwn 
You set the correct permissions!
Round 7 (of 8)!

Current permissions of "/challenge/pwn": -wx-w--wx
- the user doesn't have read permissions
* the user does have write permissions
* the user does have execute permissions
- the group doesn't have read permissions
* the group does have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
* the world does have write permissions
* the world does have execute permissions

Needed permissions of "/challenge/pwn": rw-r-xrwx
* the user does have read permissions
* the user does have write permissions
- the user doesn't have execute permissions
* the group does have read permissions
- the group doesn't have write permissions
* the group does have execute permissions
* the world does have read permissions
* the world does have write permissions
* the world does have execute permissions
hacker@permissions~permissions-setting-practice:~$ chmod u=rw,g=rx,o=rwx /challenge/pwn 
You set the correct permissions!
You've solved all 8 rounds! I have changed the ownership
of the /flag file so that you can 'chmod' it. You won't be able to read
it until you make it readable with chmod!

Current permissions of "/flag": ---------
- the user doesn't have read permissions
- the user doesn't have write permissions
- the user doesn't have execute permissions
- the group doesn't have read permissions
- the group doesn't have write permissions
- the group doesn't have execute permissions
- the world doesn't have read permissions
- the world doesn't have write permissions
- the world doesn't have execute permissions
hacker@permissions~permissions-setting-practice:~$ ls -l /flag 
---------- 1 hacker hacker 56 Oct 19 05:19 /flag
hacker@permissions~permissions-setting-practice:~$ chmod u=r /flag 
hacker@permissions~permissions-setting-practice:~$ cat /flag
pwn.college{Us-andDFsn3s0Gybcus7Q6w5jZs.QXzETO0wCO5IzW}
hacker@permissions~permissions-setting-practice:~$ 
```

搞得人很烦



# 8-The SUID Bit











