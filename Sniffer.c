#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define exit_with_error(msg) do {perror(msg); exit (EXIT_FAILURE);}while(0)

typedef struct{
    uint8_t t_protocol;
    char * source_ip;
    char * dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    char* source_if_name;
    char * dest_if_name;
    uint8_t source_mac[6];
    uint8_t dest_mac[6];
}packet_filter_t;

struct sockaddr_in source_addr, dest_addr;

int main(int argc, char ** argv){
    int c;
    char log[255];
    FILE* log_file=NULL;
    packet_filter_t packet_filter = {0, NULL,NULL,0,0,NULL,NULL};
    struct sockaddr sadr;
    int sockfd, saddr_len,bufflen;
   uint8_t *buffer = (uint8_t*)malloc(65536); //65536 is the natrual size of binary systems, 2^16
   memset(buffer,0,65536);
   sockfd= socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
   if(sockfd<0){
    exit_with_error("FAILED TO CREATE RAW SOCKET");
   }
   //29.37
    return 0;
}