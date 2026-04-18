/*
 * argv_zap.so — LD_PRELOAD shim that blanks argv[1..] from /proc/PID/cmdline
 * after the target binary has parsed its arguments.
 *
 * Rationale: exec -a can rewrite argv[0], but the remaining args (paths,
 * flags) remain visible via `ps aux`. By hooking __libc_start_main we can
 * copy argv into heap-backed storage, hand that to the real main, then
 * zero the stack-resident argv region so the kernel's cmdline reader
 * returns just argv[0].
 *
 * Usage:
 *   gcc -O2 -fPIC -shared -o argv_zap.so argv_zap.c -ldl
 *   LD_PRELOAD=/path/argv_zap.so exec -a "kmsg-watch" inotifywait …
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <sys/prctl.h>

typedef int (*main_t)(int, char **, char **);
typedef int (*libc_start_main_t)(main_t, int, char **,
                                 void (*)(void), void (*)(void),
                                 void (*)(void), void *);

static main_t real_main;

static int wrapped_main(int argc, char **argv, char **envp) {
    /* Heap-copy argv so the target keeps its arguments. */
    char **heap_argv = (char **)calloc(argc + 1, sizeof(char *));
    if (heap_argv) {
        for (int i = 0; i < argc; i++) {
            heap_argv[i] = strdup(argv[i] ? argv[i] : "");
        }
    }

    /* Zero the contiguous argv[1..] region (argv[0] stays for ps). */
    if (argc > 1 && argv[1] && argv[argc - 1]) {
        char *start = argv[1];
        char *end = argv[argc - 1] + strlen(argv[argc - 1]);
        if (end > start) memset(start, 0, (size_t)(end - start));
    }

    /* Short comm name mirrors the argv[0] disguise. */
    prctl(PR_SET_NAME, (unsigned long)"kmsg-watch", 0, 0, 0);

    return real_main(argc, heap_argv ? heap_argv : argv, envp);
}

int __libc_start_main(main_t main_fn, int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {
    real_main = main_fn;
    libc_start_main_t real = (libc_start_main_t)dlsym(RTLD_NEXT, "__libc_start_main");
    return real(wrapped_main, argc, argv, init, fini, rtld_fini, stack_end);
}
