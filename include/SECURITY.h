#ifndef SECURITY_H_
#define SECURITY_H_
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/socket.h>

#include <string>

class Base {
 public:
  int fd;  // 套接字描述符
  typedef struct loginData {
    std::string username;
    std::string password;
  } loginData;
  loginData mylogin;
  typedef struct dataPack {
    std::string deskey;
    std::string data;
  } dataPack;
  dataPack mydata;

 public:
  virtual int
  creatChannel() = 0;  // 创建网络连接通道，创建成功返回套接字描述符，创建失败返回-1
  virtual int destoryChannel() = 0;  //销毁网络通道以及公钥和私钥
  virtual int login() = 0;           // 用户登录
  virtual std::string loginStructToString() = 0;
  virtual void loginStringToStruct(const std::string& str) = 0;
  virtual std::string dataStructToString() = 0;
  virtual void dataStringToStruct(const std::string& str) = 0;

  //网络上传输公钥要进行字符串之间的转换
  virtual std::string publicKeyToString(RSA* rsaPublicKey) = 0;
  virtual RSA* stringToPublicKey(const std::string& publicKeyString) = 0;
};

class Client : public Base {
 private:
  std::string address;
  int port = 0;  // 默认值是0可以用于区分用户有没有输入固定的ip和端口
  struct sockaddr_in raddr, laddr;
  std::string desStrs;  // rsa解密后的字符串

 public:
  Client(std::string address,
         int port);  // 构造函数传入ip地址和端口号
  Client();          // 客户端可以默认不绑定ip和端口
  int creatChannel() override;
  int destoryChannel() override;
  int clientCreatChannel(int socket_d);  // 客户端具体创建网络连接通道
  void generateKeypair();                // 客户端生成公钥私钥
  std::string encry(std::string data);  // 数据加密
  std::string decry(std::string data);  // 把客户端传过来的数据进行解密
  int login() override;
  void operate();                  // 客户端发送数据的逻辑流程
  int sendData(std::string data);  // 把加密后的数据通过网络发送出去
  std::string loginStructToString() override;
  std::string dataStructToString() override;
  std::string publicKeyToString(RSA* rsaPublicKey) override;
  RSA* stringToPublicKey(const std::string& publicKeyString) override;
  void reConnect();  // 重新建立连接

  void loginStringToStruct(const std::string& str) override;
  void dataStringToStruct(const std::string& str) override;
};

class Server : public Base {
 private:
  std::string address;
  int port;
  struct sockaddr_in laddr, raddr;
  std::string desStrs;  // rsa解密后的字符串
  typedef struct RSAData {
    char serverPublicKey[2048];
    char serverPrivateKey[2048];
    char clientPublicKey[2048];
  } RSAData;
  RSAData rsaData;

 public:
  Server(std::string address,
         int port);  // 绑定服务器的本地端口和IP
  int creatChannel() override;
  int destoryChannel() override;
  int serverCreatChannel(int socket_d);  // 服务端具体创建网络连接通道
  void generateKeypair(int newsd);       // 生成服务器的秘钥对
  std::string encry(std::string data);  // 数据加密
  std::string decry(std::string data);  // 把客户端传过来的数据进行解密
  int login() override;
  int receveData();  // 接收客户端传过来的数据，并把解密后的内容显示到终端上
  void loginStringToStruct(const std::string& str) override;
  void dataStringToStruct(const std::string& str) override;
  std::string publicKeyToString(RSA* rsaPublicKey) override;
  RSA* stringToPublicKey(const std::string& publicKeyString) override;

  std::string loginStructToString() override;
  std::string dataStructToString() override;
};
#endif