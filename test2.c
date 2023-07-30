void a() {
    int foo = 1;
}

void b() {
    int foo = 2;
    a();
}

void c() {
    int foo = 3;
    b();
}

void d() {
    int foo = 4;
    c();
}

void e() {
    int foo = 5;
    d();
    int foo2 = 7;
}

void f() {
    int foo = 6;
    e();
}

int main() {
    f();
}