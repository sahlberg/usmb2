

all: ps2-usmb2-cat

ps2-usmb2-cat: ps2-usmb2-cat.o usmb2.o
	gcc ps2-usmb2-cat.o usmb2.o -o ps2-usmb2-cat
