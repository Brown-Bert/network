#include <stdio.h>
#include <stdlib.h>

#include <cstdlib>

#include "SECURITY.h"

int main() {
  Server* server = new Server("0.0.0.0", 8888);
  int socket_d = server->creatChannel();
  server->serverCreatChannel(socket_d);
  // server->generateKeypair();
  server->receveData();
  server->destoryChannel();
  free(server);
  exit(0);
}