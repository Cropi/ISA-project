# Compiler
CC=g++

# Flags
FLAGS=-std=c++11 -static-libstdc++

TARGET=dns-export
MODULES=arg_parser pcap_parser interface syslogmessage
OBJS = $(addprefix obj/, $(addsuffix .o,$(MODULES)))



all: $(TARGET)

.PHONY: clean

$(TARGET) : $(OBJS) main.cpp constants.h
	$(CC) $(FLAGS) $(OBJS) main.cpp -o $@ -lpcap

obj/%.o : %.cpp %.h constants.h
	mkdir -p obj
	$(CC) $(FLAGS) -c -o $@ $<

zip:
	zip xlakat01 Makefile *.cpp *.h *.hpp

clean:
	rm -rf obj/ $(TARGET) xlakat01.zip
