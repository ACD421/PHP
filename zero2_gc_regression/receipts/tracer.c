// glibc allocator tracer for p24 — LD_PRELOAD, __libc_* backend (no dlsym recursion).
#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern void *__libc_malloc(size_t);
extern void  __libc_free(void *);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

#define HS (1 << 17)
#define HM (HS - 1)
static uintptr_t hkey[HS];
static size_t    hval[HS];
static int tracefd = -1;

static void hput(uintptr_t p, size_t s) {
    uintptr_t i = (p >> 4) & HM;
    while (hkey[i] && hkey[i] != p) i = (i + 1) & HM;
    hkey[i] = p; hval[i] = s;
}
static size_t hpop(uintptr_t p) {
    uintptr_t i = (p >> 4) & HM;
    while (hkey[i] && hkey[i] != p) i = (i + 1) & HM;
    if (hkey[i] == p) { size_t s = hval[i]; hkey[i] = 1; return s; }
    return 0;
}
static void line(char op, void *p, size_t a, size_t b, void *ra) {
    char buf[128];
    int n = snprintf(buf, sizeof buf, "%c %p %zu %zu %p\n", op, p, a, b, ra);
    if (n > 0) (void)!write(tracefd, buf, n);
}

__attribute__((constructor)) static void tinit(void) {
    tracefd = open("/tmp/p24_trace.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

void *malloc(size_t s) {
    void *r = __libc_malloc(s);
    if (tracefd >= 0) { hput((uintptr_t)r, s); line('m', r, s, 0, __builtin_return_address(0)); }
    return r;
}
void *calloc(size_t n, size_t s) {
    void *r = __libc_calloc(n, s);
    if (tracefd >= 0) { hput((uintptr_t)r, n * s); line('c', r, n * s, 0, __builtin_return_address(0)); }
    return r;
}
void free(void *p) {
    if (tracefd >= 0 && p) { size_t s = hpop((uintptr_t)p); line('f', p, s, 0, __builtin_return_address(0)); }
    __libc_free(p);
}
void *realloc(void *p, size_t s) {
    void *r = __libc_realloc(p, s);
    if (tracefd >= 0) { size_t old = p ? hpop((uintptr_t)p) : 0; hput((uintptr_t)r, s); line('r', r, old, s, __builtin_return_address(0)); }
    return r;
}
