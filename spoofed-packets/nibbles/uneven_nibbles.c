#include <stdio.h>

struct FlagsAndFragmentOffset {
	unsigned short res: 1;
	unsigned short df: 1;
	unsigned short mf: 1;
	unsigned short fragment_offset: 13;
};

int main(void) {
	struct FlagsAndFragmentOffset nibbles;
	nibbles.res = 1;
	nibbles.df = 0;
	nibbles.mf = 1;
	nibbles.fragment_offset = 78;

	printf("Size of flags and fragment offset: %ld bytes.\n", sizeof(struct FlagsAndFragmentOffset));
	printf("Res: %d.\n", nibbles.res);
	printf("df: %d.\n", nibbles.df);
	printf("mf: %d.\n", nibbles.mf);
	printf("fragment_offset: %d.\n", nibbles.fragment_offset);
	return 0;
}
