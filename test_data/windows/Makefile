all: basic basic-opt clean_useless

basic: basic.cpp
	clang-cl.exe -c -Z7 -O0 -I. basic.cpp -o basic64.obj
	clang.exe -shared -g2 -o basic64.dll basic64.obj
	clang-cl.exe -c -Z7 -O0 -m32 -I. basic.cpp -o basic32.obj
	clang.exe -shared -m32 -g2 -o basic32.dll basic32.obj
	clang-cl.exe -c -Z7 -O0 -m32 -I. basic.cpp -o basic32-min.obj
	clang.exe -shared -g0 -m32 -o basic32-min.dll basic32-min.obj
	dump_syms.exe basic32.dll > basic32.old.sym
	dump_syms.exe basic64.dll > basic64.old.sym
	pdbcopy.exe basic32-min.pdb basic32-min-stripped.pdb -p
	mv basic32-min-stripped.pdb basic32-min.pdb
	dump_syms.exe basic32-min.dll > basic32-min.old.sym
	makecab.exe basic32.pdb basic32.pd_

basic-opt: basic.cpp
	clang-cl.exe -c -Z7 -O2 -I. basic.cpp -o basic64.obj
	clang.exe -shared -g2 -o basic-opt64.dll basic64.obj
	clang-cl.exe -c -Z7 -O2 -m32 -I. basic.cpp -o basic32.obj
	clang.exe -shared -m32 -g2 -o basic-opt32.dll basic32.obj
	dump_syms.exe basic-opt32.dll > basic-opt32.old.sym
	dump_syms.exe basic-opt64.dll > basic-opt64.old.sym

clean_useless:
	rm *.obj *.exp *.ilk *.lib

clean:
	rm *.pdb *.dll
