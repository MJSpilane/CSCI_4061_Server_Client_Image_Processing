#include "aes.h"

/* Code built primarily from OpenSSL's documentation on their AES implementation */

void handleErrors(void) {
    fprintf(stderr, "Encryption/Decryption error\n");
    exit(1);
}

void aes_encrypt(FILE *infile, FILE *outfile, const unsigned char *key) {
    // Find input file size
    fseek(infile, 0, SEEK_END);
    size_t file_size = ftell(infile);
    rewind(infile);

    // Copy input file to plaintext
    unsigned char *plaintext = (unsigned char *)malloc(file_size);
    fread(plaintext, 1, file_size, infile);

    // Initialize Cipher context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) <= 0) {
        handleErrors();
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx)) <= 0) {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) <= 0) {
        handleErrors();
    }

    int len;
    unsigned char *ciphertext = (unsigned char *)malloc(file_size + EVP_CIPHER_CTX_block_size(ctx));

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, file_size) <= 0) {
        handleErrors();
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
        handleErrors();
    }

    ciphertext_len += len;

    fwrite(ciphertext, 1, ciphertext_len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
}

void aes_decrypt(FILE *infile, FILE *outfile, const unsigned char *key) {
    fseek(infile, 0, SEEK_END);
    size_t file_size = ftell(infile);
    rewind(infile);

    unsigned char *ciphertext = (unsigned char *)malloc(file_size);
    fread(ciphertext, 1, file_size, infile);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) <= 0) {
        handleErrors();
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx)) <= 0) {
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) <= 0) {
        handleErrors();
    }

    int len;
    unsigned char *plaintext = (unsigned char *)malloc(file_size);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, file_size) <= 0) {
        handleErrors();
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        handleErrors();
    }

    plaintext_len += len;

    fwrite(plaintext, 1, plaintext_len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);
}

void aes_generate_key(unsigned char *key, size_t key_size) {
    if (RAND_bytes(key, key_size) <= 0) {
        handleErrors();
    }
}

void aes_example() {
    OpenSSL_add_all_algorithms();
    const char *input_filename = "input.txt";
    const char *encrypted_filename = "encrypted.txt";
    const char *decrypted_filename = "decrypted.txt";

    // 256-bit key (32 bytes)
    unsigned char key[32];

    // Generate a random key
    aes_generate_key(key, sizeof(key));

    // Open input and output files
    FILE *infile = fopen(input_filename, "rb");
    FILE *encrypted_file = fopen(encrypted_filename, "wb");
    FILE *decrypted_file = fopen(decrypted_filename, "wb");

    if (!infile || !encrypted_file || !decrypted_file) {
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }

    // Encrypt the file
    aes_encrypt(infile, encrypted_file, key);
    printf("File encrypted successfully.\n");

    fclose(infile);
    fclose(encrypted_file);

    // Open encrypted file and output file for decryption
    infile = fopen(encrypted_filename, "rb");
    decrypted_file = fopen(decrypted_filename, "wb");

    if (!infile || !decrypted_file ){
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }

    // Decrypt the file
    aes_decrypt(infile, decrypted_file, key);
    printf("File decrypted successfully.\n");

    fclose(infile);
    fclose(decrypted_file);

    EVP_cleanup();
}

int main() {
    aes_example();

    return 0;
}