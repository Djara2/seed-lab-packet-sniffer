#include <stdio.h>

// only 1 byte is required as the 8 bits of the unsigned char
// are shared.
struct thing {
	unsigned char high: 4;
	unsigned char low: 4;
};

int main(void) {
	struct thing nibbles; 
	nibbles.high = 2;
	nibbles.low = 4;
	printf("Size of nibbles: %ld bytes.\n", sizeof(struct thing));
	return 0;
}
