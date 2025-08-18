BIN  = ps2-usmb2-cat
OBJS = ps2-usmb2-cat.o usmb2.o unicode.o ntlm.o md4c.o hmac-md5.o md5.o
CFLAGS += -Os -Wall
CFLAGS += -DUSMB2_FEATURE_OPENDIR -DUSMB2_FEATURE_WRITE -DUSMB2_FEATURE_NTLM -DUSMB2_FEATURE_UNICODE -DUSMB2_FEATURE_CLOSE

all: $(BIN)

clean:
	rm -f $(OBJS) $(BIN)

%.o: %.c
	gcc -c $^ -o $@ $(CFLAGS)

$(BIN): $(OBJS)
	gcc $(OBJS) -o $(BIN)

