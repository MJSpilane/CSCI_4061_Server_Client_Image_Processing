#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

unsigned char* rsa_encrypt(unsigned char *source, unsigned int inputLen, int *outputLen, const char *publicKey);
unsigned char* rsa_decrypt(unsigned char *source, int inputlen, const char *privateKey);
void rsa_generate_keys(char* publicName, char* privateName);
void rsa_example();

#endif // RSA_H