#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "proto.h"

int main(int argc, char *argv[]) {
  int sd;
  struct msg_st data;
  struct sockaddr_in saddr;

  //   if (argc < 2) {
  //     fprintf(stderr, "Using...\n");
  //     exit(1);
  //   }

  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) {
    perror("socket()");
    exit(1);
  }
  int val = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(int)) < 0) {
    perror("setsockopt");
    exit(1);
  }

  strcpy((char *)data.name, "yzx");
  data.math = htonl(100);
  data.chinese = htonl(100);
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(atoi(RCVPORT));
  inet_pton(AF_INET, "255.255.255.255", &saddr.sin_addr);
  int res = sendto(sd, &data, sizeof(data), 0, (struct sockaddr *)&saddr,
                   sizeof(saddr));
  if (res < 0) {
    perror("sendto");
    exit(1);
  }
  puts("OK");
  close(sd);
  exit(0);
}