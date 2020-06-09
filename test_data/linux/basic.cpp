__attribute__((always_inline)) int inline_1(int x)
{
    int y = x + 1;
    int z = y + 3 * x;
    return z;
}

__attribute__((always_inline)) int inline_2(int x)
{
    return inline_1(x);
}

__attribute__((always_inline)) int inline_3(int x)
{
    return inline_2(x);
}

__attribute__((always_inline)) int inline_4(int x)
{
    return inline_3(x);
}

__attribute__((noinline)) int foo(int x)
{
    int y = x + 1;
    int z = inline_4(y * 2);
    y = x * 5;
    z *= 3;
    z += inline_2(y * inline_4(y + 3));

    return y + z;
}

int main(int argc, char ** argv)
{
    return foo(argc);
}
