OBJ := SpecialProxy
CC := gcc
CFLAGS := -O2 -Wall -pthread
#如果是安卓编译
ifeq ($(ANDROID_DATA),/data)
	CFLAGS := -O2 -pie -Wall
	SHELL = /system/bin/sh
endif


all : main.o http.o dns.o timeout.o
	$(CC) $(CFLAGS) $(DEFS) -o $(OBJ) $^
	strip $(OBJ)
	-chmod 777 $(OBJ) 2>&-

.c.o : 
	$(CC) $(CFLAGS) $(DEFS) -c $<

clean : 
	rm -f *.o
