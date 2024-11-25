# 1-

*代表任意的内容

```

```



# 2

![image-20241123143316562](./05%20File%20Globbing.assets/image-20241123143316562.png)



# 3[]

```bash
$/challenge/run file_[absh]
```

单个通配符的有限集合

![image-20241123143510382](./05%20File%20Globbing.assets/image-20241123143510382.png)



# 4

```bash
$/challenge/run /challenge/files/file_[absh]
```

跟3一样，绝对地址，目录要是~

![image-20241123143721965](./05%20File%20Globbing.assets/image-20241123143721965.png)

# 5

```bash
hacker@globbing~mixing-globs:/challenge/files$ /challenge/run [cep]*
You got it! Here is your flag!
pwn.college{ICVzEYuRduken46u0nd7U6qmMU3.QX1IDO0wCO5IzW}
```



# 6

```sh
hacker@globbing~exclusionary-globbing:/challenge/files$ /challenge/run [^pwn]*
You got it! Here is your flag!
pwn.college{Q5tnzsGtANH4D0bKsArBrR9u-HT.QX2IDO0wCO5IzW}
```

