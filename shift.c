#include <cstdio>
#include <stdint.h>

int main(void) {
	uint32_t d = 0x80000020;
	printf("%x\n", (d << 1) >> 1);
	return 0;
}