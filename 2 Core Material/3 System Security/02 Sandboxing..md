# 1

## 题目描述

> ```c
> #define _GNU_SOURCE 1
> 
> #include <stdlib.h>
> #include <stdint.h>
> #include <stdbool.h>
> #include <stdio.h>
> #include <unistd.h>
> #include <fcntl.h>
> #include <string.h>
> #include <time.h>
> #include <errno.h>
> #include <assert.h>
> #include <sys/types.h>
> #include <sys/stat.h>
> #include <sys/socket.h>
> #include <sys/wait.h>
> #include <sys/mman.h>
> #include <sys/sendfile.h>
> 
> int main(int argc, char **argv, char **envp)
> {
>     assert(argc > 0);
> 
>     printf("###\n");
>     printf("### Welcome to %s!\n", argv[0]);
>     printf("###\n");
>     printf("\n");
> 
>     setvbuf(stdin, NULL, _IONBF, 0);
>     setvbuf(stdout, NULL, _IONBF, 1);
> 
>     assert(argc > 1);
> 
>     char jail_path[] = "/tmp/jail-XXXXXX";
>     assert(mkdtemp(jail_path) != NULL);
> 
>     printf("Creating a jail at `%s`.\n", jail_path);
> 
>     assert(chroot(jail_path) == 0);
> 
>     int fffd = open("/flag", O_WRONLY | O_CREAT);
>     write(fffd, "FLAG{FAKE}", 10);
>     close(fffd);
> 
>     printf("Sending the file at `%s` to stdout.\n", argv[1]);
>     sendfile(1, open(argv[1], 0), 0, 128);
> 
> }
> ```
>
> 