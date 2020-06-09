all: basic

basic: basic.cpp
	g++ -g2 basic.cpp -o basic.full
	objcopy --only-keep-debug basic.full basic.dbg
	objcopy --strip-unneeded basic.full basic.stripped

clean:
	rm basic.full basic.stripped basic.dbg
