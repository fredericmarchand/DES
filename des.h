#ifndef DES_H
#define DES_H

class DES {

private:

    struct KeySet{
        char k[48]; 
    };

    void encryptBlock(char *plaintext, char *finalCiphertext,  KeySet *keyset, int mode);
    void generateSubKeys(char *key, KeySet *keyset);

public: 

    DES();
    ~DES();
    void DESEncrypt(char *ciphertext, char *plaintext, char *key);
    void DESDecrypt(char *plaintext, char *ciphertext, char *key);
    void tripleDESEncrypt(char *ciphertext, char *plaintext, char *key1, char *key2, char *key3);
    void tripleDESDecrypt(char *plaintext, char *ciphertext, char *key1, char *key2, char *key3);
    void generateKey(char* key); 

};

#endif
