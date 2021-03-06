#ifndef DES_H
#define DES_H

class DES {

private:

    struct KeySet{
        char k[6]; 
    };

    void encryptBlock(char *plaintext, char *finalCiphertext,  KeySet *keyset, char mode);
    void generateSubKeys(const char *key, KeySet *keyset);

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
