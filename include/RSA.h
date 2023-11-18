#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <cstring>
#include <iostream>

std::string rsaEncrypt(const std::string& plaintext, RSA* rsaPublicKey);

std::string rsaDecrypt(const std::string& ciphertext, RSA* rsaPrivateKey);