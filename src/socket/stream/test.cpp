#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
using namespace std;

int main() {
  int fd1 =
      open("/home/yzx/vscode/workspace/unixenv/src/socket/stream/server.cpp",
           O_RDONLY);
  int fd2 = dup(fd1);
  cout << fd1 << endl;
  cout << fd2 << endl;
  exit(0);
}