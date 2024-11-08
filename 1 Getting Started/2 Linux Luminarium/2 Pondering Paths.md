# Prerequisite Knowledge

> This module will teach you the basics of Linux file paths!
>
> The Linux filesystem is a "tree". That is, it has a root (written as `/`). The root of the filesystem is a directory, and every directory can contain other directories and files. You refer to files and directories by their *path*. A path from the root of the filesystem starts with `/` (that is, the root of the filesystem), and describes the set of directories that must be descended into to find the file. Every piece of the path is demarcated with another `/`.
>
> Armed with this knowledge, go forth and tackle the challenges below.

我的观点：

以/开头的描述文件或目录路径的，就是绝对地址

其他的都是相对地址



# 1-The Root

就是执行程序，执行这个位于根目录下的程序。

![image-20241106161351376](./2%20Pondering%20Paths.assets/image-20241106161351376.png)

还是要好好的读题干啊，就读题干的英语。

# 2-Program and absoiute paths

pwd，这个指令告诉你，你现在在哪个目录下工作。

运行这个程序，没了。

![image-20241106162700543](./2%20Pondering%20Paths.assets/image-20241106162700543.png)

但是不能使用相对路径。

![image-20241106162807346](./2%20Pondering%20Paths.assets/image-20241106162807346.png)



# 3-Position thy self

问题描述：切换目录

![image-20241108142850375](./2%20Pondering%20Paths.assets/image-20241108142850375.png)



# 4-Position elsewhere

所以你到底想要考察什么？

![image-20241108143008709](./2%20Pondering%20Paths.assets/image-20241108143008709.png)



# 5-Position yet elsewhere

？？？？？

![image-20241108143140149](./2%20Pondering%20Paths.assets/image-20241108143140149.png)



# 6-implicit relative paths, from /

考察你对相对地址的理解

![image-20241108143447647](./2%20Pondering%20Paths.assets/image-20241108143447647.png)



# 7-explicit relative paths, from /

问题描述：

> In most operating systems, including Linux, every directory has two implicit entries that you can reference in paths: `.` and `..`. The first, `.`, refers right to the same directory, so the following absolute paths are all identical to each other:
>
> - `/challenge`
> - `/challenge/.`
> - `/challenge/./././././././././`
> - `/./././challenge/././`
>
> The following relative paths are also all identical to each other:
>
> - `challenge`
> - `./challenge`
> - `./././challenge`
> - `challenge/.`
>
> Of course, if your current working directory is `/`, the above relative paths are equivalent to the above absolute paths.

写的真好

考察你对.和..的理解。

![image-20241108143835249](./2%20Pondering%20Paths.assets/image-20241108143835249.png)



# 8-impilcit relative path

你执行文件时，最好的习惯是，使用路径，而不是什么路径都不用。

什么叫做使用路径？

```
无论是绝对路径，（以/开头）
还是以.开头的相对路径
这些都叫做使用路径
```

什么叫做不使用路径？

```bash
直接使用文件或者目录名字
hacker@paths~implicit-relative-path:/challenge$ run
hacker@paths~implicit-relative-path:/$ challenge/run
```

如下图所示：

![image-20241108145243685](./2%20Pondering%20Paths.assets/image-20241108145243685.png)

# 9- home sweet home

哈哈哈记得这个题难倒了许多同学

如图所示：

![image-20241108145454338](./2%20Pondering%20Paths.assets/image-20241108145454338.png)

