#ifndef DES_H
#define DES_H

void DESEncrypt(char *ciphertext, char *plaintext, char *key);
void DESDecrypt(char *plaintext, char *ciphertext, char *key);
void tripleDESEncrypt(char *ciphertext, char *plaintext, char *key1, char *key2, char *key3);
void tripleDESDecrypt(char *plaintext, char *ciphertext, char *key1, char *key2, char *key3);

#endif
