#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "DES.h"
#include "RSA.h"

// 补齐密钥长度为8字节
void padKey(const char* key, char* paddedKey) {
  int len = strlen(key);
  if (len >= 8) {
    strncpy(paddedKey, key, 8);
  } else {
    strncpy(paddedKey, key, len);
    for (int i = len; i < 8; i++) {
      paddedKey[i] = '0';
    }
  }
}

// DES加密
std::string encryptDES(const std::string& plaintext, const std::string& key) {
  DES_cblock desKey;
  DES_key_schedule keySchedule;
  char paddedKey[8];
  padKey(key.c_str(), paddedKey);

  memcpy(desKey, paddedKey, 8);
  DES_set_odd_parity(&desKey);
  DES_set_key_checked(&desKey, &keySchedule);

  std::string ciphertext;
  int len = plaintext.length();
  const_DES_cblock inputBlock;
  DES_cblock outputBlock;
  for (int i = 0; i < len; i += 8) {
    memset(inputBlock, 0, 8);
    memcpy(inputBlock, plaintext.c_str() + i, std::min(8, len - i));
    DES_ecb_encrypt(&inputBlock, &outputBlock, &keySchedule, DES_ENCRYPT);
    ciphertext.append((char*)outputBlock, 8);
  }

  return ciphertext;
}

// DES解密
std::string decryptDES(const std::string& ciphertext, const std::string& key) {
  DES_cblock desKey;
  DES_key_schedule keySchedule;
  char paddedKey[8];
  padKey(key.c_str(), paddedKey);

  memcpy(desKey, paddedKey, 8);
  DES_set_odd_parity(&desKey);
  DES_set_key_checked(&desKey, &keySchedule);

  std::string plaintext;
  int len = ciphertext.length();
  const_DES_cblock inputBlock;
  DES_cblock outputBlock;
  for (int i = 0; i < len; i += 8) {
    memset(inputBlock, 0, 8);
    memcpy(inputBlock, ciphertext.c_str() + i, 8);
    DES_ecb_encrypt(&inputBlock, &outputBlock, &keySchedule, DES_DECRYPT);
    plaintext.append((char*)outputBlock, 8);
  }

  return plaintext;
}

std::string rsaEncrypt(const std::string& plaintext, RSA* rsaPublicKey) {
  int rsaLen = RSA_size(rsaPublicKey);
  std::string ciphertext;
  std::vector<unsigned char> buffer(rsaLen);

  int result = RSA_public_encrypt(
      plaintext.length(),
      reinterpret_cast<const unsigned char*>(plaintext.c_str()), buffer.data(),
      rsaPublicKey, RSA_PKCS1_PADDING);
  if (result == -1) {
    std::cerr << "RSA encryption failed." << std::endl;
    return "";
  }

  ciphertext.assign(buffer.begin(), buffer.begin() + result);
  return ciphertext;
}

std::string rsaDecrypt(const std::string& ciphertext, RSA* rsaPrivateKey) {
  int rsaLen = RSA_size(rsaPrivateKey);
  // puts("000");
  std::string plaintext;
  std::vector<unsigned char> buffer(rsaLen);
  // puts("123");
  int result = RSA_private_decrypt(
      ciphertext.length(),
      reinterpret_cast<const unsigned char*>(ciphertext.c_str()), buffer.data(),
      rsaPrivateKey, RSA_PKCS1_PADDING);
  if (result == -1) {
    std::cerr << "RSA decryption failed!!!!!!" << std::endl;
    return "";
  }
  plaintext.assign(buffer.begin(), buffer.begin() + result);
  // puts("456");
  return plaintext;
}