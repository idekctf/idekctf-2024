all:
	zig cc exploit.c exploit.s -static -o exploit -target x86_64-linux-musl -Os
	strip exploit