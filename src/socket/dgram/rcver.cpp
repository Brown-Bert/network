#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>

#include "proto.h"

int main(int argc, char* argv[]) {
  int sd, sb;
  struct sockaddr_in laddr, raddr;
  struct msg_st data;
  socklen_t raddr_len;
  socklen_t IPSTRLEN = 16;
  char ipstr[IPSTRLEN];

  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    perror("socket()");
    exit(1);
  }
  //   int val = 1;
  //   if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(int)) < 0) {
  //     perror("setsockopt");
  //     exit(1);
  //   }
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(atoi(RCVPORT));
  inet_pton(AF_INET, "0.0.0.0", &(laddr.sin_addr));
  sb = bind(sd, (const struct sockaddr*)&laddr, sizeof(laddr));
  if (sb < 0) {
    perror("bind()");
    exit(1);
  }
  raddr_len = sizeof(raddr);
  while (1) {
    recvfrom(sd, &data, sizeof(data), 0, (struct sockaddr*)&raddr, &raddr_len);
    inet_ntop(AF_INET, &raddr.sin_addr.s_addr, ipstr, IPSTRLEN);
    printf("---MESSAGE FROM %s:%d---\n", ipstr, ntohs(raddr.sin_port));
    printf("name = %s\n", data.name);
    printf("math = %d\n", ntohl(data.math));
    printf("chinese = %d\n", ntohl(data.chinese));
  }
  close(sd);
  exit(0);
}