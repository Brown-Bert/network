#include <openssl/des.h>

#include <cstring>
#include <iostream>

// 补齐密钥长度为8字节
void padKey(const char* key, char* paddedKey);

// DES加密
std::string encryptDES(const std::string& plaintext, const std::string& key);
// DES解密
std::string decryptDES(const std::string& ciphertext, const std::string& key);
// int main() {
//   std::string plaintext = "Hello, World!yzx";
//   std::string key = "mykey123";

//   std::string ciphertext = encryptDES(plaintext, key);
//   std::cout << "Ciphertext: " << ciphertext << std::endl;

//   std::string decryptedText = decryptDES(ciphertext, key);
//   std::cout << "Decrypted Text: " << decryptedText << std::endl;

//   return 0;
// }