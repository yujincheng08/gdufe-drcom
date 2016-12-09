CC = gcc
$(CC) -static -lws2_32 main.c md5.c -odrcom
