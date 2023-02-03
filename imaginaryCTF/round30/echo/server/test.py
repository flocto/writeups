test = 'asdf😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔😔\r\nFLAG_PLEASE /flag HTTP/1.1\r\nHost: localhost:7777\r\nContent-Length: 0\r\n\r\n'
print(len(test), len(test.encode()))

# from socket import *
# import time
# s = socket(AF_INET, SOCK_STREAM)
# s.connect(('localhost', 7777))
# s.send(b'''FLAG_PLEASE /flag HTTP/1.1\r
# Host: localhost:7777\r
# Content-Length: 0\r
# \r
# ''')
# time.sleep(0.1)
# print(s.recv(1024))