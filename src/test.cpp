#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "DES.h"
#include "RSA.h"
#include "SECURITY.h"

std::string publicKeyToString(RSA* rsaPublicKey);

// int main() {
//   std::string plaintext = "yzx 123456";

//   // 生成 RSA 密钥对
//   RSA* rsaKeyPair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
//   if (rsaKeyPair == nullptr) {
//     std::cerr << "RSA key generation failed." << std::endl;
//     return 1;
//   }
//   std::cout << "rsaKeyPair" << rsaKeyPair << std::endl;

//   // 获取公钥和私钥
//   RSA* rsaPublicKey = RSAPublicKey_dup(rsaKeyPair);
//   RSA* rsaPrivateKey = RSAPrivateKey_dup(rsaKeyPair);
//   printf("client private: %s\n", publicKeyToString(rsaPublicKey).c_str());
//   printf("client public: %s\n", publicKeyToString(rsaPrivateKey).c_str());

//   // 加密
//   std::string ciphertext = rsaEncrypt(plaintext, rsaPublicKey);

//   std::cout << "Ciphertext: " << ciphertext << std::endl;

//   // 解密
//   std::string decryptedText = rsaDecrypt(ciphertext, rsaPrivateKey);
//   std::cout << "Decrypted Text: " << decryptedText << std::endl;

//   // 释放密钥内存
//   RSA_free(rsaKeyPair);
//   RSA_free(rsaPublicKey);
//   RSA_free(rsaPrivateKey);

//   return 0;
// }
RSA* PublicKey;
RSA* PrivateKey;
typedef struct loginData {
  std::string username;
  std::string password;
} Data;
typedef struct dataPack {
  std::string deskey;
  std::string data;
} Pack;
std::string loginStructToString(Data& mylogin) {
  std::ostringstream oss;
  // sizeof(mylogin)
  oss << mylogin.username << " " << mylogin.password;
  return oss.str();
}
std::string dataStructToString(Pack& mydata) {
  std::ostringstream oss;
  oss << mydata.deskey << " " << mydata.data;
  return oss.str();
}
void dataStringToStruct(const std::string& str, Pack& mydata) {
  std::istringstream iss(str);
  iss >> mydata.deskey >> mydata.data;
}
std::string myencry(std::string data) {
  std::string key = "mykey123";
  // 生成 RSA 密钥对
  RSA* rsaKeyPair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
  if (rsaKeyPair == nullptr) {
    std::cerr << "RSA key generation failed." << std::endl;
  }

  // 获取公钥和私钥
  PublicKey = RSAPublicKey_dup(rsaKeyPair);
  PrivateKey = RSAPrivateKey_dup(rsaKeyPair);

  std::string ciphertext = encryptDES(data, key);
  Pack p;
  p.data = ciphertext;
  // puts(ciphertext.c_str());
  std::string res = rsaEncrypt(key, PublicKey);
  p.deskey = res;
  printf("data1: %s\n", p.data.c_str());
  printf("key1: %s\n", p.deskey.c_str());
  return dataStructToString(p);
}
std::string mydecry(std::string data) {
  Pack p;
  dataStringToStruct(data, p);
  printf("data2: %s\n", p.data.c_str());
  printf("key2: %s\n", p.deskey.c_str());
  std::string reskey = rsaDecrypt(p.deskey, PrivateKey);
  puts(reskey.c_str());
  std::string res = decryptDES(p.data, reskey);
  return res;
}

int main() {
  // std::string t1 = myencry("13579");
  // std::string t2 = mydecry(t1);
  // puts(t2.c_str());
  char buf[sizeof(int)];
  buf[0] = '1';
  buf[1] = '2';
  buf[2] = '\0';
  std::string name(buf);
  printf("%d\n", name.size());
  // puts(name.c_str());
  // printf("%d\n", atoi(name.c_str()));
  // int name = 15;
  // memcpy(buf, &name, sizeof(int));
  // int t;
  // memcpy(&t, buf, sizeof(int));
  // printf("%d\n", t);
  return 0;
}

std::string publicKeyToString(RSA* rsaPublicKey) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_RSAPublicKey(bio, rsaPublicKey) != 1) {
    // 转换失败，处理错误
    // ...
    puts("失败");
  }
  char* buffer;
  long length = BIO_get_mem_data(bio, &buffer);
  std::string publicKeyString(buffer, length);
  BIO_free_all(bio);
  return publicKeyString;
}