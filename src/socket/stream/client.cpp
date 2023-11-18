#include <arpa/inet.h>
#include <bits/types/FILE.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include <cstdlib>

#include "proto.h"

int main(int argc, char* argv[]) {
  int sd;
  struct sockaddr_in raddr;

  if (argc < 2) {
    fprintf(stderr, "Using......\n");
    exit(1);
  }

  sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    perror("socket()");
    exit(1);
  }
  raddr.sin_family = AF_INET;
  raddr.sin_port = htons(atoi(SERVERPORT));
  inet_pton(AF_INET, argv[1], &raddr.sin_addr.s_addr);
  if (connect(sd, (struct sockaddr*)&raddr, sizeof(raddr)) < 0) {
    perror("connect");
    exit(1);
  }
  FILE* fp = fdopen(sd, "r+");
  if (fp == NULL) {
    perror("fdopen()");
    exit(1);
  }
  long long timestr;
  if (fscanf(fp, FMT_TIME, &timestr) < 1) {
    perror("fprintf()");
    exit(1);
  }
  printf("%lld\n", timestr);
  fclose(fp);
  exit(0);
}