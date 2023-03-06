#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"

void run(char *prog, char ** arg) {
    int pid;
    pid = fork();
    if (pid == 0) {
        exec(prog, arg);
    }
}

int main(int argc, char** argv) {
    char charbuf[2048]; // store the argument of previous prog
    char* cmdbuf[128];
    char ** cmdp = cmdbuf;
    for (int i = 1; i < argc; i += 1) { // the first is "xargs"
        *cmdp++ = argv[i];
    }
    char c;
    memset(charbuf, '\0', 2048);
    char* p = charbuf;
    char* start = charbuf;

    while (read(0, &c, 1) > 0) {
        if (c == '\n' || c == '\0') {
            *p = '\0';
            *cmdp++ = start;
            start = p++;
            if (c == '\n') {
                run(argv[1], cmdbuf);
                memset(charbuf, '\0', 2048);
                p = charbuf;
            }
        } else {
            *p++ = c;
        }
    }
    
    if (p > charbuf) {
        *p++ = '\0';
        *cmdp++ = start;
        run(argv[1], cmdbuf);
        memset(charbuf, '\0', 2048);
        p = charbuf;
    }
    int info;
    while (wait(&info) > 0);
    exit(0);
}