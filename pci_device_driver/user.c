
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>

main() {
    int i, fd;

    char reset[2] = {'1'};
    u_int8_t result[20];

/*    char buf0[34] = {'5', '1', 
		    1, 1, 1, 1,
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    0, 0, 0, 0x61, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0};

    char buf0[34] = {'5', '1', 
		    1, 1, 1, 1,
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    0x50, 0xcf, 0x1e, 0x5c, 
		    0x2a, 0x78, 0x6f, 0x31, 
		    0xbf, 0x3f, 0x62, 0x4d, 
		    0x45, 0x44, 0x1e, 0x19};

    char buf0[34] = {'5', '0', 
		    1, 1, 1, 1,
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    0, 0, 0, 0x61, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0};


    char buf0[34] = {'4', '1', 
		    1, 1, 1, 1,
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    0xf6, 0x1c, 0x90, 0xda, 
		    0xf2, 0x11, 0xd9, 0xa6};

    char buf0[34] = {'4', '0', 
		    1, 1, 1, 1,
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    1, 1, 1, 1, 
		    0, 0, 0, 0x61, 
		    0, 0, 0, 0};


    char buf0[65] = {'3', 
		    0x61, 0x80, 0, 0,
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0,
		    0, 0, 0, 8};
*/
    char buf0[65] = {'2', 
		    0x61, 0x80, 0, 0,
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    8, 0, 0, 0,
		    0, 0, 0, 0};
/*

    char buf1[65] = {'2', 
		    '4', '3', '2', '1', 
		    '8', '7', '6', '5', 
		    '2', '1', '0', '9', 
		    '6', '5', '4', '3', 
		    '0', '9', '8', '7', 
		    '4', '3', '2', '1', 
		    '8', '7', '6', '5', 
		    '2', '1', '0', '9', 
		    '6', '5', '4', '3', 
		    '0', '9', '8', '7', 
		    '4', '3', '2', '1', 
		    '8', '7', '6', '5', 
		    '2', '1', '0', '9', 
		    '6', '5', '4', '3', 
		    '0', '9', '8', '7', 
		    '4', '3', '2', '1'};

    char buf1[65] = {'2', 
		    '1', '2', '3', '4', 
		    '5', '6', '7', '8', 
		    '9', '0', '1', '2', 
		    '3', '4', '5', '6', 
		    '7', '8', '9', '0', 
		    '1', '2', '3', '4', 
		    '5', '6', '7', '8', 
		    '9', '0', '1', '2', 
		    '3', '4', '5', '6', 
		    '7', '8', '9', '0', 
		    '1', '2', '3', '4', 
		    '5', '6', '7', '8', 
		    '9', '0', '1', '2', 
		    '3', '4', '5', '6', 
		    '7', '8', '9', '0', 
		    '1', '2', '3', '4'};
		    
    char buf2[65] = {'2', 
		    '5', '6', '7', '8', 
		    '9', '0', '1', '2', 
		    '3', '4', '5', '6', 
		    '7', '8', '9', '0', 
		    0x80, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0, 0, 0, 0, 
		    0x80, 2, 0, 0, 
		    0, 0, 0, 0};
*/
    if ((fd = open("/dev/encrypt", O_RDWR)) == -1) {
	printf("\ncan not open file ...");
	return 1;
    }

    write(fd, reset, sizeof(reset));
    write(fd, buf0, sizeof(buf0));
    read(fd, result, 16);
    printf("\nresult: ");

    for (i = 0; i < 16; i++)
	printf("%x ", result[i]);

    printf("\n");
    write(fd, buf0, sizeof(buf0));
    read(fd, result, 16);
    printf("\nresult: ");

    for (i = 0; i < 16; i++)
	printf("%x ", result[i]);

    printf("\n");
}