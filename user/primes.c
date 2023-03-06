#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

void sieve(int pLeft[2]);
int 
main(int argv, char ** argc) {
    int p[2];
    if (pipe(p) < 0) {
        exit(1);
    }
    if (fork() == 0) { // child process
        close(p[1]); // close the write side
        sieve(p);
    } else {
        close(p[0]); // close the read side
        for (int i = 2; i <= 35; i++) {
            write(p[1], &i, 4);
        }
        int end = -1;
        write(p[1], &end, 4);
    }
    wait(0);
    exit(0);
}

void
sieve(int pLeft[2]) {
    // the process holds pLeft[0]
    int sieveNum;
    int readNum;
    read(pLeft[0], &sieveNum, 4);
    if (sieveNum == -1) {
        exit(0);
    }
    printf("prime %d\n", sieveNum);
    int pRight[2];
    if (pipe(pRight) < 0) {
        exit(1);
    }
    if (fork() == 0) {
        close(pLeft[0]);
        close(pRight[1]);
        sieve(pRight);
    } else {
        close(pRight[0]);
        while(read(pLeft[0], &readNum, 4) != 0) {
            if (readNum % sieveNum != 0) {
                write(pRight[1], &readNum, 4);
            }
            if (readNum == -1) {
                break;
            }
        }
        wait(0);
        exit(0);
    }
}