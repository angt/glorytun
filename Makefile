CFLAGS=-std=c99 -g -fsanitize=address -fno-omit-frame-pointer -Wall

glorytun:

setcap: glorytun
	sudo setcap cap_net_admin+ep glorytun
