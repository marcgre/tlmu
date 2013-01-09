BASEDIR=../../..
-include $(BASEDIR)/config-host.mak
VPATH=$(SRC_PATH)/tests/tlmu/openrisc-guest

CROSS  = or32-linux-

CC      = $(CROSS)gcc
CXX     = $(CROSS)g++
AS      = $(CROSS)gcc -x assembler-with-cpp -c
LD      = $(CC)
SIZE    = $(CROSS)size

CFLAGS  = -Wall -g -O2

LDFLAGS  = -Wl,-Ttext,0x18010000
LDFLAGS += -Wl,-Tdata,0x19010000
LDFLAGS += -nostartfiles
LDLIBS  += -nostdlib -e _start

OBJS = entry.o guest.o
TARGET = guest

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(CRT) $(LDLIBS)

clean:
	$(RM) $(TARGET) $(OBJS)

