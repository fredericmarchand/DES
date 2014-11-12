#ifndef DES_H
#define DES_H

void DESEncrypt(char *ciphertext, char *plaintext, char *key);
void DESDecrypt(char *plaintext, char *ciphertext, char *key, int size);

#endif
