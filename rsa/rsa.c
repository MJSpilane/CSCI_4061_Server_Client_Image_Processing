#include "rsa.h"

/* Code built using documentation from openssl.org along with 
    file-based RSA key ideas found in this StackOverflow post:
    https://stackoverflow.com/questions/68102808/how-to-use-openssl-3-0-rsa-in-c */

unsigned char* rsa_encrypt(unsigned char *source, unsigned int inputLen, int *outputLen, const char *publicKey) {
    // Open public key file
    FILE *fd = fopen(publicKey, "r");
    if (fd == NULL) {
        perror("Error opening server public key");
        exit(EXIT_FAILURE);
    }

    // Read public key from file
    EVP_PKEY *pkey = PEM_read_PUBKEY(fd, NULL, NULL, NULL);
    fclose(fd);

    if (pkey == NULL) {
        perror("Error reading public key");
        exit(EXIT_FAILURE);
    }

    // Set up new PKEY context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    // Determine size of destination address
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, source, (size_t)inputLen);
    unsigned char* destination = OPENSSL_malloc(outlen);

    // Encrypt the source data and store in destination
    if (EVP_PKEY_encrypt(ctx, destination, &outlen, source, (size_t)inputLen) <= 0) {
        perror("Error encrypting data");
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    // Free dynamically-allocated memory
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    // Verify output and return
    *outputLen = (int)outlen;
    return destination;
}

unsigned char* rsa_decrypt(unsigned char *source, int inputLen, const char *privateKey) {
    // Open private key file
    FILE *fd = fopen("clientPrivate.txt", "r");
    if (fd == NULL) {
        perror("Error opening client private key");
        exit(EXIT_FAILURE);
    }

    // Read private key
    EVP_PKEY *pkey = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
    fclose(fd);
    if (pkey == NULL) {
        perror("Error reading client private key");
        exit(EXIT_FAILURE);
    }

    // Set up new PKEY context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    // Determine size of destination address
    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, source, (size_t)inputLen);
    unsigned char* destination = OPENSSL_malloc(outlen);

    // Decrypt the source data and store in destination
    if (EVP_PKEY_decrypt(ctx, destination, &outlen, source, (size_t)inputLen) <= 0) {
        perror("Error decrypting data");
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    // Free dynamically-allocated memory
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return destination;
}

void rsa_generate_keys(char* publicName, char* privateName){
    // Generate an RSA key pair
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (pkey == NULL) {
        perror("Error generating RSA");
        exit(EXIT_FAILURE);
    }

    // Open publicName file and write the public key to it
    FILE *fd = fopen(publicName, "wt");
    if (fd != NULL){
        PEM_write_PUBKEY(fd, pkey);
        fclose(fd);
    } else {
        perror("Error opening file");
    }

    // Open privateName file and write the private key to it
    fd = fopen(privateName, "wt");
    if (fd != NULL){
        PEM_write_PrivateKey(fd, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fd);
    } else {
        perror("Error opening file");
    }

    // Free dynamically-allocated memory
    EVP_PKEY_free(pkey);
}

void rsa_example(){
    // Generate keys once and forget about it
    rsa_generate_keys("clientPublic.txt", "clientPrivate.txt");
    rsa_generate_keys("serverPublic.txt", "serverPrivate.txt");

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Set up public and private key file names
    const char *publicKey = "clientPublic.txt";
    const char *privateKey = "clientPrivate.txt";

    // Message to encrypt:
    unsigned char *originalMessage = "8456312";
    int msgSize = strlen(originalMessage);
    printf("Original Message: %.*s\n", msgSize, originalMessage);

    // Encrypt
    int outputLen = 0;
    unsigned char *encryptedBuffer = rsa_encrypt(originalMessage, msgSize, &outputLen, publicKey);
    printf("Encrypted Message: %.*s\n", outputLen, encryptedBuffer);

    // Decrypt
    unsigned char *decryptedBuffer = rsa_decrypt(encryptedBuffer, outputLen, privateKey);
    printf("Decrypted Message: %.*s\n", outputLen, decryptedBuffer);

    // Free resources
    OPENSSL_free(encryptedBuffer);
    OPENSSL_free(decryptedBuffer);

    // Clean up OpenSSL
    ERR_free_strings();
    EVP_cleanup();
}

int main() {
    rsa_example();

    return 0;
}