#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdint.h>
#include <stdint.h>
#include <stdint.h>
#include <sqlite3.h>
#include <sodium.h>

#pragma comment(lib, "Crypt23.lib")

#define MAX_PATH_LENGTH 256
#define MAX_LINE_LENGTH 1024 
#define IV_SIZE 12

void displayErrorMessage(DWORD errorCode){}

char* getEncryptionKey(const char* encryption_key_path){}

BYTE* base64decode(const char* base64_encoded_key, DWORD* decoded_length){}

DATA_BLOB decryptData(const char* encryptedData, DWORD encryptedDataLength){}

void decrypt_payload(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted){}

void printHex(const BYTE* data, DWORD length){}

int main()
{
  char* username= getenv('USERNAME')
  if(username==NULL){
    printf("Error: Unable to get username.\n")
    return 1;
  }

  printf("Got username: %s\n",username);

  return 0;
}


