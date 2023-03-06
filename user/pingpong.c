#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define BUFSIZE 5
int main() {
    int pParentToChild[2];
    int pChildToParent[2];
    char buf[BUFSIZE];
    int pid;
    int status;
    if (pipe(pChildToParent) < 0 || pipe(pParentToChild) < 0) {
        fprintf(2, "pipe error\n");
        exit(1);
    }
    if (fork() == 0) { // child
        pid = getpid();
        read(pParentToChild[0], buf, BUFSIZE);
        printf("%d: received %s\n", pid, buf);
        write(pChildToParent[1], "pong", BUFSIZE);
    } else {
        pid = getpid();
        write(pParentToChild[1], "ping", BUFSIZE);
        read(pChildToParent[0], buf, BUFSIZE);
        wait(&status);
        printf("%d: received %s\n", pid, buf);
    }
    exit(0);
}