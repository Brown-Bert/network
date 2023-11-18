#include <stdio.h>
#include <stdlib.h>

#include <cstdlib>

#include "SECURITY.h"

int main() {
  // Client* client = new Client("127.0.0.1", 9999);
  Client* client = new Client;
  int socket_d = client->creatChannel();
  client->clientCreatChannel(socket_d);
  client->generateKeypair();
  client->operate();
  client->destoryChannel();
  free(client);
  exit(0);
}