#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_BLOCK_SIZE 16

void aes_encrypt(FILE *infile, FILE *outfile, const unsigned char *key);
void aes_decrypt(FILE *infile, FILE *outfile, const unsigned char *key);
void aes_generate_key(unsigned char *key, size_t key_size);
void aes_example();

#endif // AES_H