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

void rtcp_scan(char *host, int port_range_start, int port_range_end) {
  struct sockaddr_in *target;
  struct sockaddr_in sender;
  socklen_t sender_len = sizeof(sender);
  char packet[4];
  char response[512];
  int flags;
  int port;
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

  if ((port_range_start % 2) == 0) {
    port_range_start++;
    port_range_end++;
  }
  printf("scanning %s rtcp ports %d to %d with %lu bytes\n", host, port_range_start, port_range_end, sizeof(packet));
  port = port_range_start;
  for (;;) {
    target->sin_port = htons(port);
      sendto(udp_socket, &packet, sizeof(packet), 0, (const struct sockaddr *)target, sizeof(struct sockaddr_in));
      usleep(1 * 1000);

      int bytes_received = recvfrom(udp_socket, &response, sizeof(response), 0, (struct sockaddr *)&sender, &sender_len);
      if (bytes_received > 0) {
        printf("received %d bytes from target port %d\n", bytes_received, ntohs(sender.sin_port));
      }
      port += 2;
      if (port > port_range_end) {
        port = port_range_start;
      }
  }
  close(udp_socket);
  free(target);
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    printf("syntax: rtcpscan hostname port_range_start port_range_end\n");
    return -1;
  }

  rtcp_scan(argv[1], atoi(argv[2]), atoi(argv[3]));
  return 0;
}
