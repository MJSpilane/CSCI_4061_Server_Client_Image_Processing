# RSA dirctory

This directory contians rudimentary rsa_dectypt() and rsa_encrypt() functions along with a cryptographically-secure public/private key pair generation function all implemented using the openssl/rsa library.

Usage:

## rsa_encrypt(unsigned char *source, unsigned int inputLen, int *outputLen, const char *publicKey)
This function takes in the following parameters:
    - unsigned char *source, the source data to be encrypted
    - unsigned int inputLen, the lenght of the input (bytes)
    - int *outputLen, the lenght of the encrypted message
    - const char *publicKey, the name of the txt file containing the public key to encrypt the data

This function returns the follwowing parameters:
    - unsigned char *destination: the encypted source data using the key specified in "clientPublic.txt"

rsa_encrypt() works to encrypt an input, source, using the RSA algorithm with the public key specified in the text file publicKey.


## rsa_decrypt(unsigned char *source, int inputLen, const char *privateKey)
This function takes in the following parameters:
    - unsigned char *source, the encrypted data to be decrypted with privateKey
    - int inputLen, the length of the encrypted source data
    - const char *privateKey, the name of the txt file containing the private key to decrypt the data

This function returns the following parameters:
    - unsigned char *destination: the decrypted source data using the private key specified in the text file privateKey

rsa_decrypt() works to decrypt an input, source, using the RSA algorithm with the private key specified in the text file privateKey.

## rsa_generate_keys(char* publicName, char* privateName)
This funciton takes in the following parameters:
    - char *publicName, the name of the file to hold the public key of the key pair
    - char *privateName, the name of the file to hold the private key of the key paid

This function does not have a return value.

rsa_generate_keys() works to generate a private and public key-pair that will work together to encrypt and decrypt messages using the RSA algorithm.

## rsa_example()
This function takes in no parameters

This function does not have a return value

rsa_example() works to demonstrate the usage of rsa_generate_keys, rsa_encrypt(), and rsa_decrypt