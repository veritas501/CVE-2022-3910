#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buffer[0x10];
    fputs("Password: ", stderr);
    read(0, buffer, sizeof(buffer));
    fputs("EXIT", stderr);
    return 0;
}