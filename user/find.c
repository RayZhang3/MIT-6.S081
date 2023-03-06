#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
/*
		• Look at user/ls.c to see how to read directories.
		• Use recursion to allow find to descend into sub-directories.
		• Don't recurse into "." and "..".
		• Changes to the file system persist across runs of qemu; to get/home/luna/Desktop/6.S081/xv6-labs-2020/user/find.c a clean file system run make clean and then make qemu.
		• You'll need to use C strings. Have a look at K&R (the C book), for example Section 5.5.
		• Note that == does not compare strings like in Python. Use strcmp() instead.
		• Add the program to UPROGS in Makefile.
*/

/*
        struct dirent {
            ushort inum;
            char name[DIRSIZ];
};
*/

/*
	#define T_DIR     1   // Directory
	#define T_FILE    2   // File
	#define T_DEVICE  3   // Device
	struct stat {
	  int dev;     // File system's disk device
	  uint ino;    // Inode number
	  short type;  // Type of file
	  short nlink; // Number of links to file
	  uint64 size; // Size of file in bytes
};
*/

void find(char *path, char* target);

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Illegal argument.\n");
        exit(1);
    }
    find(".", argv[2]);
    exit(0);
}
char name[DIRSIZ + 1];

char*
fmtname(char *path)
{
  char *p;
  // Find first character after last slash.
  for(p = path+strlen(path); p >= path && *p != '/'; p--)
    ;
  p++;
  // Return blank-padded name.
  memset(name, 0, DIRSIZ + 1);
  memmove(name, p, strlen(p));
  return &name[0];
}

void find(char *path, char* target) 
{
    //printf("current search path:%s\n", path);
    char buf[512];
    char *p;
    int fd;
    struct dirent de;
    struct stat st;
    char filename[DIRSIZ + 1];

    if ((fd = open(path, 0)) < 0)
    {
        fprintf(2, "find: cannot open %s\n", path);
    }

    if (fstat(fd, &st) < 0) {
        fprintf(2, "(first)find: cannot stat first%s\n", path);
        close(fd);
        return;
    }

    switch(st.type) {
        case T_FILE:
            memset(filename, 0, DIRSIZ + 1);
            strcpy(filename, fmtname(path));
            //printf("current path: %s, current filename: %s\n", path, filename);
            if (!strcmp(filename, target)) {
                //printf("\n find the path: %s\n\n", path);
                printf("%s\n", path);
            }
            break;
        
        case T_DIR:
            if(strlen(path) + 1 + DIRSIZ + 1 > sizeof buf) {
                printf("find: path too long\n");
                break;
            }
            strcpy(buf, path);
            p = buf+strlen(buf);
            *p++ = '/'; // p is the next char of / 
            while(read(fd, &de, sizeof(de)) == sizeof(de)){
                if(de.inum == 0 || strcmp(de.name, ".") == 0 || strcmp(de.name,"..") == 0) //super block
                    continue;
                memmove(p, de.name, DIRSIZ);
                p[DIRSIZ] = 0;// terminate the filename string
                if(stat(buf, &st) < 0){
                    printf("(second)find: cannot stat  %s\n", buf);
                    memset(p, 0, DIRSIZ);
                    continue;
                }
                find(buf, target);
                memset(p, 0, DIRSIZ); // remove the file name 
                }
            break;
    }
    close(fd);     
}