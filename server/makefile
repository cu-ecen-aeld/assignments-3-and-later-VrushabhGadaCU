CC ?= gcc
CFLAGS = -Wall -Wextra -O3
TARGET = aesdsocket
SRCS = aesdsocket.c

ifdef CROSS_COMPILE
    CC = $(CROSS_COMPILE)gcc
endif

all default: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET)
