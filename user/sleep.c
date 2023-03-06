#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int 
main(int argc, char* argv[]) {
    int sleepTime;
    if (argc < 2) {
        fprintf(2, "Usage: sleep...\n");
        exit(1);
    }
    if (argc > 2) {
        fprintf(2, "Invalid arguments\n");
        exit(1);
    }
    for (int i = 1; i < argc; i += 1) {
        sleepTime = atoi(argv[i]);
        if (sleepTime < 0) {
            fprintf(2, "Negative sleeptime\n");
            exit(1);
        }
    }
    sleep(sleepTime);
    exit(0);
    
}