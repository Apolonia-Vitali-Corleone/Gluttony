# 1-cat: not the pet, but the command

先执行程序

然后读取就行了

这里是相对路径读取

![image-20241108145845407](./03%20Comprehending%20Commands.assets/image-20241108145845407.png)

# 2-catting absolute paths

这里是绝对路径读取

![image-20241108145942764](./03%20Comprehending%20Commands.assets/image-20241108145942764.png)

# 3-more catting practice

要认真审题

![image-20241108150105990](./03%20Comprehending%20Commands.assets/image-20241108150105990.png)

# 4-grepping for a needle in a haystack

学会用grep

```shell
hacker@dojo:~$ grep SEARCH_STRING /path/to/file
```

如图

![image-20241108150219703](./03%20Comprehending%20Commands.assets/image-20241108150219703.png)

# 5-listing files 

学会ls指令

![image-20241108150755416](./03%20Comprehending%20Commands.assets/image-20241108150755416.png)

我常用的ls -al

```
-l                         use a long listing format
 -a, --all                  do not ignore entries starting with .
```

![image-20241108151937755](./03%20Comprehending%20Commands.assets/image-20241108151937755.png)

第二张

![image-20241108152002680](./03%20Comprehending%20Commands.assets/image-20241108152002680.png)

再来一张（这张没必要全展示完）：

![image-20241108152024491](./03%20Comprehending%20Commands.assets/image-20241108152024491.png)



看出来什么区别了吗？

# 6-touching files 

学会使用touch创建文件

![image-20241108151130459](./03%20Comprehending%20Commands.assets/image-20241108151130459.png)

我只是发现个好玩的，似乎多加////号会被过滤掉，不允许文件名有这个。

# 7-removing files

学会rm指令

![image-20241108151700465](./03%20Comprehending%20Commands.assets/image-20241108151700465.png)

# 8-hidden files

读取.开头的文件

![image-20241108152258744](./03%20Comprehending%20Commands.assets/image-20241108152258744.png)

# 9-An Epic Filesystem Quest

说实在的，挺无聊的

![image-20241108161407831](./03%20Comprehending%20Commands.assets/image-20241108161407831.png)



![image-20241108161430129](./03%20Comprehending%20Commands.assets/image-20241108161430129.png)



![image-20241108161453913](./03%20Comprehending%20Commands.assets/image-20241108161453913.png)

# 10-making directories

mkdir

![image-20241108161631298](./03%20Comprehending%20Commands.assets/image-20241108161631298.png)

觉得无聊了

# 11-finding files

![image-20241108161938297](./03%20Comprehending%20Commands.assets/image-20241108161938297.png)

把能读的都读了

或者：

```
$ grep pwn.college $(cat $(find / -name flag))
```

直接就出来了



# 12-linking files

讲解链接这个东西。

没必要过多深入的了解这个东西。

![image-20241108163022499](./03%20Comprehending%20Commands.assets/image-20241108163022499.png)



