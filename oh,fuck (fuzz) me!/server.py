#!/usr/bin/env python
from socket import *
import select, sys, os
from subprocess import Popen, PIPE


flag = "flag{xxxxxx-xxxxxx-xxxxxx-xxxxxx-xxxxxx}"


def check_input(data):

	p = Popen('./dis.exe', stdin=PIPE)
	p.communicate(data)
	if p.returncode == -11:
		return True


def main(port):

	ss = socket()
	ss.bind(('', port))
	ss.listen(5)
	cl = [ss]
	
	while True:
		in_list = select.select(cl, [], [], 1)[0]

		for sock in in_list:

			if sock == ss:
				client_sock = ss.accept()[0]
				cl.append(client_sock)

			else:
				try:
					data = sock.recv(64)
					if check_input(data):
						sock.send(flag)
				except Exception as e:
					sock.close()
					cl.remove(sock)


if __name__ == '__main__':
	main(1337)
