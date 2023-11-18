#include "SECURITY.h"

#include <arpa/inet.h>
#include <bits/types/FILE.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#include "DES.h"
#include "RSA.h"
#define BUFSIZE 4096
std::string ADDRESS = "127.0.0.1";  // 客户端需要知道服务器的ip
int SERVERPORT = 8888;              // 客户端需要知道用户的port端口
std::string DESKEY = "mykeysdjjfhgskjhflskfgbsldkjgfbslfgsldkfgblsdfj";

RSA* ClientRsaPublicKey;   // 客户端的公钥
RSA* ClientRsaPrivateKey;  // 客户端的私钥
RSA* ServerRsaPublicKey;   // 服务器的公钥
RSA* ServerRsaPrivateKey;  // 服务器的私钥

Client::Client(std::string address, int port) {
  this->address = address;
  this->port = port;
}
Client::Client() {}
void Client::loginStringToStruct(const std::string& str) {}
void Client::dataStringToStruct(const std::string& str) {}

int Client::creatChannel() {
  int socket_d = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_d < 0) {
    perror("socket()");
    exit(1);
  }
  int val = 1;
  if (setsockopt(socket_d, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0) {
    perror("setsockopt()");
    exit(1);
  }
  return socket_d;
}

int Client::destoryChannel() {
  RSA_free(ClientRsaPublicKey);
  RSA_free(ClientRsaPrivateKey);
  RSA_free(ServerRsaPublicKey);
  RSA_free(ServerRsaPrivateKey);
  close(fd);
  return 0;
}

int Client::clientCreatChannel(int socket_d) {
  if (this->port != 0) {
    this->laddr.sin_family = AF_INET;
    this->laddr.sin_port = htons(this->port);
    inet_pton(socket_d, this->address.c_str(), &this->laddr.sin_addr.s_addr);
    if (bind(socket_d, (const struct sockaddr*)&this->laddr,
             sizeof(this->laddr)) < 0) {
      perror("bind()");
      exit(1);
    }
  }
  this->raddr.sin_family = AF_INET;
  this->raddr.sin_port = htons(SERVERPORT);
  // std::cout << SERVERPORT << std::endl;
  // std::cout << ADDRESS << std::endl;
  inet_pton(AF_INET, ADDRESS.c_str(), &this->raddr.sin_addr.s_addr);
  if (connect(socket_d, (struct sockaddr*)&this->raddr, sizeof(raddr)) < 0) {
    perror("connect");
    exit(1);
  }
  this->fd = socket_d;
  return 0;
}

void Client::reConnect() {
  this->raddr.sin_family = AF_INET;
  this->raddr.sin_port = htons(SERVERPORT);
  // std::cout << SERVERPORT << std::endl;
  // std::cout << ADDRESS << std::endl;
  inet_pton(AF_INET, ADDRESS.c_str(), &this->raddr.sin_addr.s_addr);
  if (connect(this->fd, (struct sockaddr*)&this->raddr, sizeof(raddr)) < 0) {
    perror("connect");
    exit(1);
  }
}

void Client::generateKeypair() {
  // 生成 RSA 密钥对
  RSA* rsaKeyPair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
  if (rsaKeyPair == nullptr) {
    std::cerr << "RSA key generation failed." << std::endl;
    exit(1);
  }

  // 获取公钥和私钥
  ClientRsaPublicKey = RSAPublicKey_dup(rsaKeyPair);
  ClientRsaPrivateKey = RSAPrivateKey_dup(rsaKeyPair);
  // printf("client private: %s\n",
  //        publicKeyToString(ClientRsaPrivateKey).c_str());
  // printf("client public: %s\n",
  // publicKeyToString(ClientRsaPublicKey).c_str());

  // 交换公钥
  char buf[8192];
  std::string publickey = publicKeyToString(ClientRsaPublicKey);
  // printf("client public: %s\n", publickey.c_str());
  // 给服务器发送信号交换密钥
  char signaltoserver[9] = "exchange";
  int res = write(this->fd, signaltoserver, sizeof(signaltoserver));
  if (res < 0) {
    perror("write()");
  }
  res = read(this->fd, buf, 8192);
  if (res < 0) {
    perror("read");
  }
  puts(buf);
  res = write(this->fd, publickey.c_str(), publickey.size());
  if (res < 0) {
    perror("write()");
  }
  res = read(this->fd, buf, 8192);
  if (res < 0) {
    perror("read");
  }
  std::string key = buf;
  // printf("server public: %s\n", buf);
  ServerRsaPublicKey = stringToPublicKey(key);
  puts("交换公钥成功");
  // close(fd);
}

std::string Client::encry(std::string data) {
  std::string desStrs = encryptDES(data, DESKEY);
  mydata.deskey = DESKEY;
  mydata.data = desStrs;
  // printf("ddddd: %s\n", desStrs.c_str());
  std::string res = dataStructToString();
  // puts(publicKeyToString(ServerRsaPublicKey).c_str());
  std::string ciphertext = rsaEncrypt(res, ServerRsaPublicKey);
  return ciphertext;
}
std::string Client::decry(std::string data) {
  // puts("123");
  std::string decryptedText = rsaDecrypt(data, ClientRsaPrivateKey);
  // puts("123");
  dataStringToStruct(decryptedText);
  // puts("123");
  // printf("\nkey: %s\n", mydata.deskey.c_str());
  std::string desStrs = decryptDES(this->mydata.data, this->mydata.deskey);
  // puts("123");
  this->desStrs = desStrs;
  return desStrs;
}

int Client::sendData(std::string data) {
  // puts(publicKeyToString(ServerRsaPublicKey).c_str());
  int len = sizeof(data);
  // char buf[BUFSIZE];
  char buf[BUFSIZE];
  // buf = data.c_str();
  // printf("data: \n%s\n", data.c_str());
  // printf("data: %d\n", data.size());
  long long i;
  for (i = 0; i < data.size(); i++) {
    if ((i % (BUFSIZE - 1) == 0) && (i != 0)) {
      buf[BUFSIZE - 1] = '\0';
      int res = write(this->fd, buf, BUFSIZE);
      if (res < 0) {
        perror("write()");
      }
      read(fd, buf, 4);
      // puts("pppp");
      puts(buf);
    }
    int index = i % (BUFSIZE - 1);
    buf[index] = data[i];
  }
  buf[i] = '\0';
  int res = write(this->fd, buf, i + 1);
  if (res < 0) {
    perror("write()");
  }
  // std::string temp = encry("EOF");
  // if (strcmp(data.c_str(), temp.c_str())) {
  read(fd, buf, 4);
  // puts("13579");
  puts(buf);
  // }
  // printf("%d\n", strlen(buf));
  // printf("%d\n", i);
  return 0;
}

int Client::login() {
  std::string username;
  std::string password;
  std::string strs;
  std::string encrystrs;
  char buf[sizeof(int) + 1];
  std::cout << "输入用户名：";
  std::cin >> username;
  std::cout << "输入密码：";
  std::cin >> password;
  mylogin.username = username;
  mylogin.password = password;
  std::string tempt = loginStructToString();
  // printf("tempt: %d\n", tempt.size());
  encrystrs = encry(tempt);
  // printf("加密：%s\n", encrystrs.c_str());
  sendData(encrystrs);
  // 发送结束标志
  std::string end = "EOF";
  sendData(encry(end));
  int res = read(this->fd, buf, sizeof(int) + 1);
  if (res < 0) {
    perror("read");
  }
  int rt;
  // puts(buf);
  memcpy(&rt, buf, sizeof(int));
  // printf("bufsdfg : %d\n", rt);
  if (rt == 1) {
    // close(fd);
    return 1;  // 登录成功
  } else {
    return 0;
  }
}

void Client::operate() {
  // 重新建立通道
  // printf("fd : %d\n", fd);
  // clientCreatChannel(creatChannel());
  // printf("fd : %d\n", fd);
  int choice;
  int flag = 0;
  std::string data;
  int loginFlag = 0;
  while (1) {
    if (loginFlag == 0) {
      std::cout << "1、登录\n2、结束\n输入选择:";
    } else {
      std::cout << "1、传输数据\n2、结束传输(退出登录)\n输入选择:";
    }
    std::cin >> choice;
    // std::string tttt;
    // std::cin >> tttt;
    // printf("tttt: %s\n", tttt.c_str());
    switch (choice) {
      case 1:
        if (loginFlag == 0) {
          if (login() == 1) {
            loginFlag = 1;
            puts("登录成功");
          } else {
            puts("登录失败");
          }
        } else {
          // 重新建立通道
          // printf("fd : %d\n", fd);
          // clientCreatChannel(creatChannel());
          // printf("fd : %d\n", fd);
          // 发送开始标志
          std::string start = "START";
          sendData(encry(start));
          while (1) {
            std::cout << "输入数据(EOF表示结束): ";
            std::cin >> data;
            if (data == "EOF") {
              break;
            } else {
              sendData(encry(data));
            }
          }
          // 发送结束标志
          std::string end = "EOF";
          sendData(encry(end));
        }
        break;
      case 2:
        if (loginFlag == 1) {
          loginFlag = 0;
          // 发送结束标志
          std::string end = "LOGOUT";
          sendData(encry(end));
        } else {
          // 发送结束标志
          std::string end = "END";
          sendData(encry(end));
          flag = 1;
        }
        break;
      default:
        std::cout << "输入有误，重新输入\n";
        // std::cin >> choice;
        break;
    }
    if (flag) break;
  }
  // close(fd);
}

std::string Client::loginStructToString() {
  // sizeof(mylogin)
  char buf[4096];
  char intbuf[sizeof(int)];
  int index = 0;
  int len = mylogin.username.size();
  // int len = 100;
  memcpy(intbuf, &len, sizeof(int));
  // puts(intbuf);
  // int t;
  // memcpy(&t, intbuf, sizeof(int));
  for (int i = 0; i < sizeof(int); i++) {
    buf[index] = intbuf[i];
    // printf("int: %d\n", intbuf[i]);
    index++;
  }
  // printf("len: %d\n", len);
  // printf("t: %d\n", t);
  const char* res = mylogin.username.c_str();
  for (int i = 0; i < mylogin.username.size(); i++) {
    buf[index] = res[i];
    index++;
  }
  len = mylogin.password.size();
  memcpy(intbuf, &len, sizeof(int));
  for (int i = 0; i < sizeof(int); i++) {
    buf[index] = intbuf[i];
    index++;
  }
  const char* name = mylogin.password.c_str();
  for (int i = 0; i < mylogin.password.size(); i++) {
    buf[index] = name[i];
    index++;
  }
  buf[index] = '\0';
  // printf("index: %d\n", index);
  std::string result(buf, index);
  // printf("result: %d\n", result.size());
  return result;
}
std::string Client::dataStructToString() {
  char buf[4096];
  char intbuf[sizeof(int)];
  int index = 0;
  int len = mydata.deskey.size();
  memcpy(intbuf, &len, sizeof(int));
  for (int i = 0; i < sizeof(int); i++) {
    buf[index] = intbuf[i];
    index++;
  }
  const char* res = mydata.deskey.c_str();
  for (int i = 0; i < mydata.deskey.size(); i++) {
    buf[index] = res[i];
    index++;
  }
  len = mydata.data.size();
  memcpy(intbuf, &len, sizeof(int));
  for (int i = 0; i < sizeof(int); i++) {
    buf[index] = intbuf[i];
    index++;
  }
  const char* name = mydata.data.c_str();
  for (int i = 0; i < mydata.data.size(); i++) {
    buf[index] = name[i];
    index++;
  }
  buf[index] = '\0';
  std::string result(buf, index);
  return result;
}
std::string Client::publicKeyToString(RSA* rsaPublicKey) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_RSAPublicKey(bio, rsaPublicKey) != 1) {
    // 转换失败，处理错误
    // ...
    puts("CLient publicKeyToString失败");
  }
  char* buffer;
  long length = BIO_get_mem_data(bio, &buffer);
  std::string publicKeyString(buffer, length);
  BIO_free_all(bio);
  return publicKeyString;
}
RSA* Client::stringToPublicKey(const std::string& publicKeyString) {
  RSA* rsaPublicKey = RSA_new();
  BIO* bio = BIO_new_mem_buf(publicKeyString.data(), publicKeyString.size());
  if (PEM_read_bio_RSAPublicKey(bio, &rsaPublicKey, nullptr, nullptr) ==
      nullptr) {
    // 解码失败，处理错误
    // ...
    puts("Client stringToPublicKey失败");
  }
  BIO_free_all(bio);
  return rsaPublicKey;
}

Server::Server(std::string address, int port) {
  this->address = address;
  this->port = port;
  ADDRESS = address;
  SERVERPORT = port;
}

std::string Server::loginStructToString() {}
std::string Server::dataStructToString() {}

int Server::creatChannel() {
  int socket_d = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_d < 0) {
    perror("socket()");
    exit(1);
  }
  int val = 1;
  if (setsockopt(socket_d, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0) {
    perror("setsockopt()");
    exit(1);
  }
  return socket_d;
}

int Server::destoryChannel() {
  RSA_free(ServerRsaPublicKey);
  RSA_free(ServerRsaPrivateKey);
  RSA_free(ClientRsaPublicKey);
  RSA_free(ClientRsaPrivateKey);
  close(this->fd);
  return 0;
}

int Server::serverCreatChannel(int socket_d) {
  this->laddr.sin_family = AF_INET;
  this->laddr.sin_port = htons(this->port);
  inet_pton(socket_d, this->address.c_str(), &this->laddr.sin_addr.s_addr);
  if (bind(socket_d, (const struct sockaddr*)&this->laddr,
           sizeof(this->laddr)) < 0) {
    perror("bind()");
    exit(1);
  }
  this->fd = socket_d;
  if (listen(this->fd, 100) < 0) {
    perror("lsiten()");
    exit(1);
  }
  return 0;
}

void Server::generateKeypair(int newsd) {
  // 生成 RSA 密钥对
  RSA* rsaKeyPair = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
  if (rsaKeyPair == nullptr) {
    std::cerr << "RSA key generation failed." << std::endl;
    exit(1);
  }

  // 获取公钥和私钥
  ServerRsaPublicKey = RSAPublicKey_dup(rsaKeyPair);
  ServerRsaPrivateKey = RSAPrivateKey_dup(rsaKeyPair);
  // printf("server private: %s\n",
  //        publicKeyToString(ServerRsaPrivateKey).c_str());
  // printf("server public: %s\n",
  // publicKeyToString(ServerRsaPublicKey).c_str());
  socklen_t len = sizeof(raddr);
  char ipbuf[16];
  char buf[8192];
  // int newsd = accept(this->fd, (struct sockaddr*)&raddr, &len);
  inet_ntop(AF_INET, &raddr.sin_addr.s_addr, ipbuf, sizeof(ipbuf));
  // printf("CLIENT: %s:%d\n", ipbuf, ntohs(raddr.sin_port));
  int res = read(newsd, buf, 8192);
  if (res < 0) {
    perror("read");
  }
  // printf("client public: %s\n", buf);
  ClientRsaPublicKey = stringToPublicKey(std::string(buf));
  std::string publickey = publicKeyToString(ServerRsaPublicKey);
  // printf("server public: %s\n", publickey.c_str());
  res = write(newsd, publickey.c_str(), publickey.size());
  if (res < 0) {
    perror("write()");
  }
  // close(newsd);
  puts("交换公钥成功");
}
std::string Server::encry(std::string data) {
  std::string desStrs = encryptDES(data, DESKEY);
  this->mydata.deskey = DESKEY;
  this->mydata.data = desStrs;
  std::string res = dataStructToString();
  // puts(publicKeyToString(ServerRsaPublicKey).c_str());
  std::string ciphertext = rsaEncrypt(res, ClientRsaPublicKey);
  return ciphertext;
}
std::string Server::decry(std::string data) {
  // puts(publicKeyToString(ClientRsaPublicKey).c_str());
  // puts("进入");
  // printf("data: %s\n", data.c_str());
  std::string decryptedText = rsaDecrypt(data, ServerRsaPrivateKey);
  // printf("%s\n", decryptedText.c_str());
  dataStringToStruct(decryptedText);
  // printf("dddd: %s\n", mydata.deskey.c_str());
  std::string desStrs = decryptDES(mydata.data, mydata.deskey);
  return desStrs;
}

int Server::login() {
  loginStringToStruct(this->desStrs);
  // printf("passwd : %s\n", mylogin.password.c_str());
  // std::string pwd("123456");
  if (!strcmp(mylogin.password.c_str(), "123456")) {  // 测试
    // puts("147");
    return 1;
  }
  return 0;
}
int Server::receveData() {
  socklen_t len = sizeof(raddr);
  int newsd;
  pid_t pid;
  char ipbuf[16];
  int loginFlag = 0;
  // int pipefd[2];
  // if (pipe(pipefd) == -1) {
  //   perror("pipe()");
  //   exit(1);
  // }
  // int s = 0;
  while (1) {
    newsd = accept(this->fd, (struct sockaddr*)&raddr, &len);
    // printf("sss: %d\n", s);
    // s++;
    if (newsd < 0) {
      perror("accept()sfdg");
      exit(1);
    }
    inet_ntop(AF_INET, &raddr.sin_addr.s_addr, ipbuf, sizeof(ipbuf));
    printf("CLIENT: %s:%d\n", ipbuf, ntohs(raddr.sin_port));
    pid = fork();
    if (pid < 0) {
      perror("fork()");
      exit(1);
    }
    if (pid == 0) {
      close(fd);
      char buf[BUFSIZE];
      while (1) {
        int num = read(newsd, buf, BUFSIZE);
        // printf("num : %d\n", num);
        if (num == 0) break;
        if (!strcmp(buf, "exchange")) {
          // close(pipefd[0]);  // 关闭读端
          puts("开始交换公钥");
          char respone[4];
          respone[0] = 'G';
          respone[1] = 'E';
          respone[2] = 'T';
          respone[3] = '\0';
          if (write(newsd, respone, 4) < 0) {
            perror("write()");
          }
          generateKeypair(newsd);
          // memcpy(rsaData.serverPublicKey,
          //        publicKeyToString(ServerRsaPublicKey).c_str(),
          //        publicKeyToString(ServerRsaPublicKey).size());
          // memcpy(rsaData.serverPrivateKey,
          //        publicKeyToString(ServerRsaPrivateKey).c_str(),
          //        publicKeyToString(ServerRsaPrivateKey).size());
          // memcpy(rsaData.clientPublicKey,
          //        publicKeyToString(ClientRsaPublicKey).c_str(),
          //        publicKeyToString(ClientRsaPublicKey).size());
          // write(pipefd[1], &rsaData, sizeof(RSAData));
          // close(pipefd[1]);  // 写完之后关闭写入端
          continue;
        }
        std::string strs(buf, num - 1);
        // puts(strs.c_str());
        // strs = strs.substr(0, strs.size() - 1);
        // printf("%d\n", num);
        // puts(buf);
        // for (long long i = 0; i < num - 1; i++) {
        //   strs += buf[i];
        // }
        // strs += '\0';
        // printf("%s\n", strs.c_str());
        // printf("%d\n", strs.size());
        std::string desRes = decry(strs);
        // printf("resdes: %s\n", desRes.c_str());
        char respone[4];
        respone[0] = 'G';
        respone[1] = 'E';
        respone[2] = 'T';
        respone[3] = '\0';
        if (write(newsd, respone, 4) < 0) {
          perror("write()");
        }
        // puts(desRes.c_str());
        // printf("desStrsdddd: %s\n", desRes.c_str());
        // puts("123");
        if (!strcmp(desRes.c_str(), "END")) {
          puts("END");
          loginFlag = 0;
          break;
        }
        if (!strcmp(desRes.c_str(), "LOGOUT")) {
          puts("LOGOUT");
          loginFlag = 0;
          continue;
        }
        if (!strcmp(desRes.c_str(), "START")) loginFlag = 1;
        if (!strcmp(desRes.c_str(), "EOF")) {
          // puts("456");
          if (loginFlag == 0) {
            // puts("789");
            int res = login();
            char t[sizeof(int) + 1];

            memcpy(t, &res, sizeof(int));
            t[sizeof(int)] = '\0';
            // std::cout << "res " << res << std::endl;
            write(newsd, t, sizeof(int) + 1);
            if (res == 1) {
              loginFlag = 1;
              puts("登陆成功");
              continue;
            }
          } else {
            puts("PASSEND");
            continue;
          }
        }
        if (loginFlag == 1) {
          puts(desRes.c_str());
        }
        this->desStrs = desRes;
      }
      close(newsd);
      exit(0);
      // if (strcmp(buf, "EOF")) {
      //   break;
      // }
      // puts("跳出");
    }
    // wait(NULL);
    // close(pipefd[1]);  // 关闭写端
    // read(pipefd[0], &rsaData, sizeof(RSAData));
    // close(pipefd[0]);  // 关闭读端
    // puts("111111111");
    // printf("%s\n", rsaData.clientPublicKey);
    // std::string t1(rsaData.serverPublicKey);
    // ServerRsaPublicKey = stringToPublicKey(t1);
    // std::string t2(rsaData.serverPrivateKey);
    // ServerRsaPrivateKey = stringToPublicKey(t2);
    // std::string t3(rsaData.clientPublicKey);
    // ClientRsaPublicKey = stringToPublicKey(t3);
    // puts("22222222");
    close(newsd);
  }
}

void Server::loginStringToStruct(const std::string& str) {
  const char* strs = str.c_str();
  char intbuf[sizeof(int)];
  char buf[4096];
  int len;
  int index = 0;
  for (int i = 0; i < sizeof(int); i++) {
    intbuf[i] = strs[index];
    index++;
  }
  memcpy(&len, intbuf, sizeof(int));
  for (int i = 0; i < len; i++) {
    buf[i] = strs[index];
    index++;
  }
  buf[index] = '\0';
  std::string name(buf, len);
  mylogin.username = name;
  for (int i = 0; i < sizeof(int); i++) {
    intbuf[i] = strs[index];
    index++;
  }
  memcpy(&len, intbuf, sizeof(int));
  for (int i = 0; i < len; i++) {
    buf[i] = strs[index];
    index++;
  }
  buf[index] = '\0';
  std::string pwd(buf, len);
  mylogin.password = pwd;
}
void Server::dataStringToStruct(const std::string& str) {
  const char* strs = str.c_str();
  // printf("sss: %d\n", str.size());
  char intbuf[sizeof(int)];
  char buf[4096];
  int len;
  int index = 0;
  for (int i = 0; i < sizeof(int); i++) {
    intbuf[i] = strs[index];
    index++;
  }
  // intbuf[index] = '\0';
  memcpy(&len, intbuf, sizeof(int));
  // printf("len: %d\n", len);
  for (int i = 0; i < len; i++) {
    buf[i] = strs[index];
    index++;
  }
  buf[index] = '\0';
  std::string key(buf, len);
  mydata.deskey = key;
  for (int i = 0; i < sizeof(int); i++) {
    intbuf[i] = strs[index];
    index++;
  }
  memcpy(&len, intbuf, sizeof(int));
  for (int i = 0; i < len; i++) {
    buf[i] = strs[index];
    index++;
  }
  buf[index] = '\0';
  std::string data(buf, len);
  mydata.data = data;
}
std::string Server::publicKeyToString(RSA* rsaPublicKey) {
  if (rsaPublicKey == NULL) {
    puts("空的");
  }
  BIO* bio = BIO_new(BIO_s_mem());
  if (PEM_write_bio_RSAPublicKey(bio, rsaPublicKey) != 1) {
    // 转换失败，处理错误
    // ...
    puts("Server publicKeyToString失败");
  }
  char* buffer;
  long length = BIO_get_mem_data(bio, &buffer);
  std::string publicKeyString(buffer, length);
  BIO_free_all(bio);
  return publicKeyString;
}
RSA* Server::stringToPublicKey(const std::string& publicKeyString) {
  RSA* rsaPublicKey = RSA_new();
  BIO* bio = BIO_new_mem_buf(publicKeyString.data(), publicKeyString.size());
  if (PEM_read_bio_RSAPublicKey(bio, &rsaPublicKey, nullptr, nullptr) ==
      nullptr) {
    // 解码失败，处理错误
    // ...
    puts("Server stringToPublicKey失败");
  }
  BIO_free_all(bio);
  return rsaPublicKey;
}
