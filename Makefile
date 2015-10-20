CFLAGS=-std=c99 -fsanitize=address -fno-omit-frame-pointer

glorytun:

setcap: glorytun
	sudo setcap cap_net_admin+ep glorytun
