CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = writer
SRCS = writer.c

ifneq ($(CROSS_COMPILE),)
    CC = $(CROSS_COMPILE)gcc
else
     $(info Using default compiler: $(CC))
endif



all : $(TARGET)
	${CC} $(CFLAGS) -c $(SRCS) -o $(TARGET).o
	${CC} $(CFLAGS) $(TARGET).o -o $(TARGET)
clean :
	rm -f $(TARGET) *.o