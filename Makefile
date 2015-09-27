CC=gcc
CFLAGS=-fPIC -c -Wall -g -lzmq -lczmq -lcrypto 
LDFLAGS=-shared -g -fPIC -lzmq -lczmq -lssl -lcrypto 
EXEC=solhsm_engine.so
SRC= $(wildcard *.c)
SRC+= $(wildcard ./lib/*.c)
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
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo 'Finished building target: $@'
	@echo ' '

.PHONY: clean cleanall

clean:
	rm -rf *.o *.d
	rm -rf ./lib/*.o ./lib/*.d
cleanall:
	rm -rf *.o *.d
	rm -rf ./lib/*.o ./lib/*.d
	rm -rf $(EXEC)

install: 
    sudo mkdir /usr/lib/engines/
	sudo cp ./solhsm_engine.so /usr/lib/engines/solhsm_engine.so
