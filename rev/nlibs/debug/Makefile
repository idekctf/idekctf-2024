all: clean gen

clean:
	rm -f src/main.c99

gen:
	python gen_sources.py
	gcc -E -C src/main.c -o src/main.c99
	python clean.py
	python obf.py
	cp src/*.h build/

test:
	gcc -g src/main.c -o src/main