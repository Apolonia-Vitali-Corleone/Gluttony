讲解curl的用法，以及http的基础知识。

# CURL

参数

```
-X + method
不用默认就是get
```



# 1

## 描述

> Send an HTTP request using curl

## exp

```shell
$ curl -X GET "http://127.0.0.1:80"
pwn.college{4Ili2tY1uXsUAJkXqwun9-ZP4ue.QX4YjMzwCO5IzW}
$ curl 127.0.0.1:80
pwn.college{4Ili2tY1uXsUAJkXqwun9-ZP4ue.QX4YjMzwCO5IzW}
```



# 2

## 描述

> Send an HTTP request using nc

## exp

```bash
hacker@talking-web~level2:~$ nc 127.0.0.1 80
GET /flag HTTP/1.1

HTTP/1.1 200 OK
Server: Werkzeug/3.0.6 Python/3.8.10
Date: Thu, 31 Oct 2024 07:42:44 GMT
Content-Length: 56
Server: pwn.college
Connection: close

pwn.college{0DLzz8a2UX-74GQ8h9bHzbZlhP2.QX5YjMzwCO5IzW}

hacker@talking-web~level2:~$ 
```



# 3

## 描述

> Send an HTTP request using python

## exp

```python
import requests 
x = requests.get("127.0.0.1:80")                                       print(x.text)   
```



# 4



