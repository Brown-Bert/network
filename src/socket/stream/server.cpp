#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <ctime>

#include "proto.h"

int main(int argc, char *argv[]) {
  int sd, newsd;
  struct sockaddr_in laddr, raddr;
  char ipbuf[16];
  pid_t pid;

  sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    perror("socket()");
    exit(1);
  }
  int val = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0) {
    perror("setsockopt()");
    exit(1);
  }
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(atoi(SERVERPORT));
  inet_pton(sd, "0.0.0.0", &laddr.sin_addr.s_addr);
  if (bind(sd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
    perror("bind()");
    exit(1);
  }

  if (listen(sd, 100) < 0) {
    perror("lsiten()");
    exit(1);
  }
  socklen_t len = sizeof(raddr);
  while (1) {
    printf("%d\n", newsd);
    newsd = accept(sd, (struct sockaddr *)&raddr, &len);
    printf("%d\n", newsd);
    if (newsd < 0) {
      perror("accept()");
      exit(1);
    }
    pid = fork();
    if (pid < 0) {
      perror("fork()");
      exit(1);
    }
    if (pid == 0) {
      close(sd);
      inet_ntop(AF_INET, &raddr.sin_addr.s_addr, ipbuf, sizeof(ipbuf));
      printf("CLIENT: %s:%d\n", ipbuf, ntohs(raddr.sin_port));
      char timstr[1024];
      int timelen = sprintf(timstr, FMT_TIME, (long long)time(NULL));
      if (send(newsd, timstr, timelen, 0) < 0) {
        perror("send()");
        exit(1);
      }
      close(newsd);
      exit(0);
    }
    close(newsd);
  }
  int i = 0;
  exit(0);
}