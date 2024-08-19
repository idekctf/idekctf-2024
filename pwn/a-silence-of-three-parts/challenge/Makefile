all:
	gcc chal.c -o chal -Wl,-z,now -fstack-protector-all -pie -o chal
	python3 patch.py
	pwnq patch --rpath . --interp ./ld-linux-x86-64.so.2 chal patched
	cp patched ../healthcheck