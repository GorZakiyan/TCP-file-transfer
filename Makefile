CC = cc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS = -lcrypto
PROGRAMS = sender encoder decoder listener
.PHONY: all clean test
all: $(PROGRAMS)
$(PROGRAMS): transfer.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
test: all
	python3 tests.py
clean:
	rm -f $(PROGRAMS)
