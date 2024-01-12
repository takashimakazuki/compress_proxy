CC  = gcc
PKGCONF ?= pkg-config
CFLAGS = -Wall -g -D DOCA_LOGGING_ALLOW_DLOG
INCLUDES  = -I/opt/mellanox/doca/include -I./include
LIBDIR  = -L/opt/mellanox/doca/lib/aarch64-linux-gnu/
LIBS  = -ldoca_comm_channel
LIBS += -ldoca_compress
LIBS += -ldoca_common
LIBS += -ldoca_argp
LIBS += $(shell $(PKGCONF) --libs ucx)
LIBS += $(shell $(PKGCONF) --libs doca)
CFLAGS += -D DOCA_LOGGING_ALLOW_DLOG -D DOCA_ALLOW_EXPERIMENTAL_API 

TARGET_MAIN  = compress_proxy
TARGET_UCX_EXAMPLE = ucx_client_server_example
TARGET_UCX_HELLO_EXAMPLE = ucp_hello_world
TARGETS = $(TARGET_MAIN) $(TARGET_UCX_EXAMPLE) $(TARGET_UCX_HELLO_EXAMPLE)

SRC = pack.c
SRC += utils.c
OBJS    = $(SRC:.c=.o)

.PHONY:all
all: $(TARGETS)

$(TARGET_MAIN): $(OBJS) $(TARGET_MAIN).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $(TARGET_MAIN).c
	$(CC) $(OBJS) $(TARGET_MAIN).o $(LIBDIR) $(LIBS) -o $@

$(TARGET_UCX_EXAMPLE): $(OBJS) $(TARGET_UCX_EXAMPLE).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $(TARGET_UCX_EXAMPLE).c
	$(CC) $(OBJS) $(TARGET_UCX_EXAMPLE).o $(LIBDIR) $(LIBS) -o $@

$(TARGET_UCX_HELLO_EXAMPLE): $(OBJS) $(TARGET_UCX_HELLO_EXAMPLE).c
	$(CC) $(CFLAGS) $(INCLUDES) -c $(TARGET_UCX_HELLO_EXAMPLE).c
	$(CC) $(OBJS) $(TARGET_UCX_HELLO_EXAMPLE).o $(LIBDIR) $(LIBS) -o $@

$(OBJS): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(SRC)


clean:
	-rm -f $(OBJS) $(TARGETS) *.d
