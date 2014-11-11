#ifndef DES_H
#define DES_H

void DESEncrypt(char *ciphertext, char *plaintext, char *key, int size);
void DESDecrypt(char *ciphertext, char *plaintext, char *key, int size);

#endif
