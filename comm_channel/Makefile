CC  = gcc
PKGCONF ?= pkg-config
CFLAGS = -Wall -g -D DOCA_LOGGING_ALLOW_DLOG
INCLUDES  = -I/opt/mellanox/doca/include
LIBDIR_ARM  = -Lopt_arm/mellanox/doca/lib/aarch64-linux-gnu/ -Lusr_arm/lib/aarch64-linux-gnu
LIBDIR_X86  = -L/opt/mellanox/doca/lib/x86_64-linux-gnu/
LIBS  = -ldoca_comm_channel
LIBS += -ldoca_common
LIBS += -ldoca_compress
LIBS += -ldoca_argp
LIBS += $(shell $(PKGCONF) --libs doca)
CFLAGS += -D DOCA_LOGGING_ALLOW_DLOG -D DOCA_ALLOW_EXPERIMENTAL_API 

TARGET_MAIN_SERVER = cc_server
TARGET_MAIN_CLIENT = cc_client
TARGETS = $(TARGET_MAIN_SERVER) $(TARGET_MAIN_CLIENT)
SRC = common.c
SRC += doca_utils.c
SRC += cc_common.c
OBJS    = $(SRC:.c=.o)

.PHONY:all
all: $(TARGETS)

$(TARGET_MAIN_SERVER): $(OBJS) $(TARGET_MAIN_SERVER).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $(TARGET_MAIN_SERVER).c
	$(CC) $(OBJS) $(TARGET_MAIN_SERVER).o $(LIBDIR_ARM) $(LIBS) -o $@


$(TARGET_MAIN_CLIENT): $(OBJS) $(TARGET_MAIN_CLIENT).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $(TARGET_MAIN_CLIENT).c
	$(CC) $(OBJS) $(TARGET_MAIN_CLIENT).o $(LIBDIR_X86) $(LIBS) -o $@


$(OBJS): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) $(INCLUDES)


clean:
	-rm -f $(OBJS) $(TARGETS) *.d *.o
