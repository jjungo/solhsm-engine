CC=gcc
override CFLAGS+=-c -lczmq -lsodium  -Wall -Wextra
LDFLAGS=-lzmq -lczmq -lssl -lcrypto
EXEC=generate_cert
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)

all: $(EXEC)

-include $(OBJ:.o=.d)

.c.o:	
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Compiler'
	$(CC) $(CFLAGS) -o $@ $<
	@echo 'Finished building: $<'
	@echo ' '

$(EXEC): $(OBJ)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Linker'
	$(CC) -o $(OUT)$@ $^ $(LDFLAGS)
	@echo 'Finished building target: $@'
	@echo ' '

.PHONY: clean cleanall

clean:
	rm -rf *.o *.d

cleanall:
	rm -rf *.o *.d
	rm -rf $(EXEC)
