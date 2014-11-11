/*
 * Frederic Marchand
 * 3-DES
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 64
#define ROUNDS 16
#define MODE_ENCRYPTION 0
#define MODE_DECRYPTION 1

#define DEBUG 0 

typedef struct {
    char k[48];
} KeySet;

int IP[] ={ 58, 50, 42, 34, 26, 18, 10, 2, 
            60, 52, 44, 36, 28, 20, 12, 4, 
            62, 54, 46, 38, 30, 22, 14, 6, 
            64, 56, 48, 40, 32, 24, 16, 8, 
            57, 49, 41, 33, 25, 17,  9, 1, 
            59, 51, 43, 35, 27, 19, 11, 3, 
            61, 53, 45, 37, 29, 21, 13, 5, 
            63, 55, 47, 39, 31, 23, 15, 7};

int inverseIP[] = { 40, 8, 48, 16, 56, 24, 64, 32, 
                    39, 7, 47, 15, 55, 23, 63, 31, 
                    38, 6, 46, 14, 54, 22, 62, 30, 
                    37, 5, 45, 13, 53, 21, 61, 29, 
                    36, 4, 44, 12, 52, 20, 60, 28, 
                    35, 3, 43, 11, 51, 19, 59, 27, 
                    34, 2, 42, 10, 50, 18, 58, 26, 
                    33, 1, 41,  9, 49, 17, 57, 25 };

int S1[][16] = {{14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0, 7},
              { 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3, 8}, 
              { 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5, 0}, 
              {15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13}};

int S2[][16] = {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, 
              {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
              {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, 
              {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};

int S3[][16] = {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
             {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
             {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, 
             {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

int S4[][16] = {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, 
              {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, 
              {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, 
              {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};

int S5[][16] = {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, 
              {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, 
              {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, 
              {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};

int S6[][16] = {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, 
              {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, 
              {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, 
              {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};

int S7[][16] = {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, 
              {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
              {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, 
              {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};

int S8[][16] = {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, 
              {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
              {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, 
              {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

int EBitSelectionTable[] = {32,  1,  2,  3,  4,  5, 
                             4,  5,  6,  7,  8,  9, 
                             8,  9, 10, 11, 12, 13, 
                            12, 13, 14, 15, 16, 17, 
                            16, 17, 18, 19, 20, 21, 
                            20, 21, 22, 23, 24, 25, 
                            24, 25, 26, 27, 28, 29, 
                            28, 29, 30, 31, 32, 1 };

int P[] = { 16,  7, 20, 21, 
            29, 12, 28, 17, 
             1, 15, 23, 26, 
             5, 18, 31, 10, 
             2,  8, 24, 14, 
            32, 27,  3,  9, 
            19, 13, 30,  6, 
            22, 11,  4, 25 };

int keyShifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

int PC1[] = {57, 49, 41, 33, 25, 17,  9, 
              1, 58, 50, 42, 34, 26, 18, 
             10,  2, 59, 51, 43, 35, 27, 
             19, 11,  3, 60, 52, 44, 36,

             63, 55, 47, 39, 31, 23, 15, 
              7, 62, 54, 46, 38, 30, 22, 
             14,  6, 61, 53, 45, 37, 29, 
             21, 13,  5, 28, 20, 12, 4};

int PC2[] = {14, 17, 11, 24,  1,  5, 
              3, 28, 15,  6, 21, 10, 
             23, 19, 12,  4, 26,  8, 
             16,  7, 27, 20, 13,  2, 
             41, 52, 31, 37, 47, 55, 
             30, 40, 51, 45, 33, 48, 
             44, 49, 39, 56, 34, 53, 
             46, 42, 50, 36, 29, 32};

void generateKey(char* key)
{
    char temp[2];
    for (int i = 0; i < 64; ++i) 
    {
        sprintf(temp, "%d", rand()%2);
        key[i] = temp[0];
    }
    key[64] = '\0';
}

void initialPermutation(char *text, char *output)
{
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        output[i] = text[IP[i]-1];
    }
}

void inverseInitialPermutation(char *text, char *output)
{
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        output[i] = text[inverseIP[i]-1];
    }
}

int getBit(char value, int pos)
{
    return ((value & (1 << pos)) >> pos);
}

void setBit(char *num, int pos)
{
    *num |= (1 << pos);
}

void clearBit(char *num, int pos)
{
    *num &= ~(1 << pos);
}

void setBitState(char *num, int pos, int value)
{
    if (value == 0)
    {
        clearBit(num, pos);
    }
    else
    {
        setBit(num, pos);
    }
}

void bitArrayToByteArray(char *input, char *output, int bitLen, int byteSize)
{
    int p = 0;
    int i = 0;
    while (i < bitLen)
    {
        for (int j = byteSize-1; j >= 0; --j)
            setBitState(&output[p], j, input[i++]);
        ++p;
    }
}

void byteArrayToBitArray(char *input, char *output, int bitLen, int byteSize)
{
    int p = 0;
    int i = 0;
    while (i < bitLen)
    {
        for (int j = byteSize-1; j >= 0; --j)
            output[i++] = getBit(input[p], j);
        ++p;
    }
}

int leftRotate(char *key, int length, int count)
{
    for (int i = 0; i < count; ++i)
    {
        char temp = key[0];
        for (int l = 0; l < length-1; ++l)
        {
            key[l] = key[l+1];
        }
        key[length-1] = temp;
    }
}

void combineArrays(char *A1, char *A2, char *out, int n1, int n2)
{
    int total = n1 + n2;
    for (int i = 0; i < total; ++i)
    {
        if (i < n1)
            out[i] = A1[i];
        else
            out[i] = A2[i-n1];
    }
}

void generateSubKeys(char *key, KeySet *keyset)
{
    char C[28];
    char D[28];
    char K[56];
    
    memset(C, 0, sizeof(C));
    memset(D, 0, sizeof(D));
    for (int i = 0; i < 56; ++i)
    {
        if (i < 28)
            C[i] = key[PC1[i]-1];
        else
            D[i-28] = key[PC1[i]-1];
    }

    for (int num = 0; num < 16; ++num)
    {
        memset(K, 0, sizeof(K));
        leftRotate(C, 28, keyShifts[num]);
        leftRotate(D, 28, keyShifts[num]);
        combineArrays(C, D, K, 28, 28);
        for (int i = 0; i < 48; ++i)
        {
            keyset[num].k[i] = K[PC2[i]-1];
        }
    }
}

void expand(char *text, char *output)
{
    for (int b = 0; b < 48; ++b)
    {
        output[b] = text[EBitSelectionTable[b]-1];
    }
}

void XOR(char *text, char *key, char *output, int len)
{
    for (int i = 0; i < len; ++i)
    {
        output[i] = (text[i] ^ key[i]);   
    }
}

void permute(char *text, char *output)
{
    for (int i = 0; i < 32; ++i)
    {
        output[i] = text[P[i]-1];
    }
}

void substitutionBox(char *text, char *permuttedArray)
{
    char byteArray[8];
    char bitArray[64];
    int bit = 0;
    memset(byteArray, 0, sizeof(byteArray));
    memset(bitArray, 0, sizeof(bitArray));
    for (int box = 1; box <= 8; ++box)
    {
        char row = 0;
        char col = 0;
        setBitState(&row, 1, text[bit++]);
        setBitState(&col, 3, text[bit++]);
        setBitState(&col, 2, text[bit++]);
        setBitState(&col, 1, text[bit++]);
        setBitState(&col, 0, text[bit++]);
        setBitState(&row, 0, text[bit++]);
        switch (box)
        {
            case 1:
                byteArray[box-1] = S1[row][col];
                break;
            case 2:
                byteArray[box-1] = S2[row][col];
                break;
            case 3:
                byteArray[box-1] = S3[row][col];
                break;
            case 4:
                byteArray[box-1] = S4[row][col];
                break;
            case 5:
                byteArray[box-1] = S5[row][col];
                break;
            case 6:
                byteArray[box-1] = S6[row][col];
                break;
            case 7:
                byteArray[box-1] = S7[row][col];
                break;
            case 8:
                byteArray[box-1] = S8[row][col];
                break;
        }
    }
    byteArrayToBitArray(byteArray, bitArray, 32, 4);

#if DEBUG == 1
    printf ("SBOX: ");
    for (int j = 0; j < 32; ++j)
        printf("%d", bitArray[j]);
    printf ("\n\n");
#endif

    permute(bitArray, permuttedArray);

#if DEBUG == 1
    printf ("P: ");
    for (int j = 0; j < 32; ++j)
        printf("%d", permuttedArray[j]);
    printf ("\n\n");
#endif
}

//Block Size 64 bits
void encryptBlock(char *plaintext, char *finalCiphertext,  KeySet *keyset, int mode)
{
    int round, endRound;
    char ciphertext[64];
    char expandedResult[48];
    char xorResult[48];
    char substitutedResult[32];
    char L[32];
    char R[32];
    char temp[32];
    
    if (mode == MODE_ENCRYPTION)
    {
        round = -1;
        endRound = ROUNDS-1;
    }
    else if (mode == MODE_DECRYPTION)
    {
        round = ROUNDS;
        endRound = 0;
    }
    
    memset(L, 0, sizeof(L));
    memset(R, 0, sizeof(R));
    memset(ciphertext, 0, sizeof(ciphertext));
    
    initialPermutation(plaintext, ciphertext);
    
    for (int i = 0; i < 64; ++i)
    {
        if (i < 32)
            L[i] = ciphertext[i];
        else
            R[i-32] = ciphertext[i];
    }

    while (round != endRound)
    {
        if (mode == MODE_ENCRYPTION)
            round++;
        else if (mode == MODE_DECRYPTION)
            round--;
    //for (int i = 0; i < ROUNDS; ++i)
    //{
#if DEBUG == 1
        printf ("L%d: ", i);
        for (int j = 0; j < 32; ++j)
            printf("%d", L[j]);
        printf ("\nR%d: ", i);
        for (int j = 0; j < 32; ++j)
            printf("%d", R[j]);
        printf ("\n\n");
#endif

        expand(R, expandedResult);

#if DEBUG == 1
        printf ("E: ");
        for (int j = 0; j < 48; ++j)
            printf("%d", expandedResult[j]);
        printf ("\n\n");
#endif

        XOR(expandedResult, keyset[round].k, xorResult, 48);

#if DEBUG == 1
        printf ("K XOR E: ");
        for (int j = 0; j < 48; ++j)
            printf("%d", xorResult[j]);
        printf ("\n\n");
#endif

        substitutionBox(xorResult, substitutedResult);

        memcpy(temp, R, sizeof(R));
        XOR(L, substitutedResult, R, 32);
        memcpy(L, temp, sizeof(L));
    }

    memset(ciphertext, 0, sizeof(ciphertext));
    combineArrays(R, L, ciphertext, 32, 32);
    inverseInitialPermutation(ciphertext, finalCiphertext);
}

void DESEncrypt(char *plaintext, char *ciphertext, char *key)
{
    KeySet keyset[16];
    generateSubKeys(key, keyset);
    //For each block (implement CBC)
    encryptBlock(plaintext, ciphertext, keyset, MODE_ENCRYPTION);
}

void DESDecrypt(char *ciphertext, char *plaintext, char *key)
{
    KeySet keyset[16];
    generateSubKeys(key, keyset);
    //For each block (implement CBC)
    encryptBlock(ciphertext, plaintext, keyset, MODE_DECRYPTION);
}

void tripleDESEncrypt(char *plaintext, char *ciphertext, char *key1, char *key2, char *key3)
{
    KeySet keyset1[16];
    KeySet keyset2[16];
    KeySet keyset3[16];
    char tempCipher1[65];
    char tempCipher2[65];

    generateSubKeys(key1, keyset1);
    generateSubKeys(key2, keyset2);
    generateSubKeys(key3, keyset3);

    //For each block (implement CBC)
    encryptBlock(plaintext, tempCipher1, keyset1, MODE_ENCRYPTION);
    encryptBlock(tempCipher1, tempCipher2, keyset2, MODE_DECRYPTION);
    encryptBlock(tempCipher2, ciphertext, keyset3, MODE_ENCRYPTION);
}

void tripleDESDecrypt(char *ciphertext, char *plaintext, char *key1, char *key2, char *key3)
{
    KeySet keyset1[16];
    KeySet keyset2[16];
    KeySet keyset3[16];
    char tempCipher1[65];
    char tempCipher2[65];

    generateSubKeys(key1, keyset1);
    generateSubKeys(key2, keyset2);
    generateSubKeys(key3, keyset3);

    //For each block (implement CBC)
    encryptBlock(ciphertext, tempCipher1, keyset1, MODE_DECRYPTION);
    encryptBlock(tempCipher1, tempCipher2, keyset2, MODE_ENCRYPTION);
    encryptBlock(tempCipher2, plaintext, keyset3, MODE_DECRYPTION);
}

int main()
{
    char key1[65];
    char key2[65];
    char key3[65];
    
    //char key[65] =   {0,0,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,0,1,1,0,0,0,0,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,0,1,1,1,1,0,1,1,1,0,1,0,1,1,1,1,0};
    char block[65] = {0,1,0,0,0,0,0,1,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,1,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,0,0,0};
    char ciphertext[65];

    //Generate Keys
    generateKey(key1);
    generateKey(key2);
    generateKey(key3);

    //Run tests

    printf ("ciphertext: \n");

    for (int i = 0; i < 64; ++i)
    {
        printf("%d", ciphertext[i]);
    }
    printf("\n");

    return 0;
}


