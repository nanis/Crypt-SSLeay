#include <stdio.h>
#include <openssl/opensslv.h>

int main(void) {
    puts(OPENSSL_VERSION_TEXT);
    return 0;
}
