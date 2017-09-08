CC = gcc
drom:
	$(CC) -static main.c md5.c -odrcom -lws2_32 
