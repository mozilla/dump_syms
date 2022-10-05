all: basic

basic: basic.cpp
	g++ -g2 basic.cpp -o basic.full
	objcopy --only-keep-debug basic.full basic.dbg
	objcopy --strip-unneeded basic.full basic.stripped
	# Make mini debuginfo
	nm basic.full --format=posix --defined-only | awk '{ if ($$2 == "T" || $$2 == "t" || $$2 == "D") print $$1 }' | sort > keep_symbols
	objcopy -S --remove-section .gdb_index --remove-section .comment --keep-symbols=keep_symbols basic.dbg mini_debuginfo
	xz -f mini_debuginfo
	cp basic.stripped basic.minidebuginfo
	objcopy --add-section .gnu_debugdata=mini_debuginfo.xz basic.minidebuginfo
	rm keep_symbols mini_debuginfo.xz

clean:
	rm basic.full basic.stripped basic.dbg basic.minidebuginfo
