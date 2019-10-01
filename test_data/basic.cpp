// test_dll.cpp : Defines the exported functions for the DLL application.
//

//#include "stdafx.h"
#include <string>

#define DllExport __declspec( dllexport )

void test1(int * x) {
	*x = 23;
}

void test2(int x, unsigned y) {
	return;
}

void test3(int x, unsigned y, short z) {
	return;
}

void test4(int x, unsigned y, unsigned short z, double * t) {
	return;
}

void test5(int * x, unsigned y, unsigned short z, const double * t, const std::string u) {
	return;
}

void test6(const double * const x, const std::string & y, std::string && z) {
	return;
}

int test7(decltype(&test4)) {
	return 0;
}

int test8(decltype(&test7)) {
	return 0;
}

int test9(decltype(&test8)) {
	return 0;
}

unsigned long ***************** test10(char *& x) {
	return nullptr;
}


class DllExport A {
public:
	A() {}
	A(const A &) = delete;
	A(A && a) {}
	~A() {}

	void meth1(int) { }
	void meth1(double) { }
	void meth1(short, signed char) {}

protected:
	void meth2(int) { 
		return;
	}
	A & meth2(double) { 
		return *this;
	}
	static void meth2(short, signed char) {
		return;
	}

private:
	struct B {
		void meth3() {
			return;
		}
	};

	B meth4(A *, B &&) {
		return B();
	}
};