#include <stdio.h>

int main(void) {

#ifdef __MINGW32__
    printf("__MINGW32__ is defined\n");
#else
    printf("__MINGW32__ is NOT defined\n");
#endif

#ifdef _WIN32
    printf("_WIN32 is defined\n");
#else
    printf("_WIN32 is NOT defined\n");
#endif

    return 0;
}