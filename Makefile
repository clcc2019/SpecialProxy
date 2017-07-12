OBJ := SpecialProxy
CC := gcc
CFLAGS := -O3 -Wall -pthread

all : main.o http.o dns.o
	$(CC) $(CFLAGS) $(DEFS) -o $(OBJ) $^
	strip $(OBJ)
	-chmod 777 $(OBJ) 2>&-

.c.o : 
	$(CC) $(CFLAGS) $(DEFS) -c $<

clean : 
	rm -f *.o
