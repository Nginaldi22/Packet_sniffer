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
   while(1){
    static struct option long_options[]={
        {"sip", required_argument,NULL,'s'},
        {"dip", required_argument,NULL,'d'},
        {"sport", required_argument,NULL,'p'},
        {"dort", required_argument,NULL,'o'},
        {"sif", required_argument,NULL,'i'},
        {"dif", required_argument,NULL,'g'},
        {"logfile", required_argument,NULL,'f'},
        {"tcp", no_argument,NULL,'t'},
        {"udp", no_argument,NULL,'u'},
        {0,0,0,0}
    };
    c = getopt_long(argc,argc,"tus:d:p:o:i:g:f:",long_options,NULL); //sets optarg
    if(c==-1){
        break;
    }
    switch(c){
        case 't':
            packet_filter.t_protocol=IPPROTO_TCP;
            break;
        case 'u':
            packet_filter.t_protocol=IPPROTO_UDP;
            break;
        case 'p':
            packet_filter.source_port=atoi(optarg);
            break;
        case 'o':
            packet_filter.dest_port=atoi(optarg);
            break;
        case 's':
            packet_filter.source_ip=optarg;
            break;
        case 'd':
            packet_filter.dest_ip=optarg;
            break;
        case 'i':
            packet_filter.source_if_name=optarg;
            break;
        case 'g':
            packet_filter.dest_if_name=optarg;
            break;
        case 'f':
            strcpy(log,optarg);
            break;
        default:
            abort();
    }
   }
   printf("t_protocal: %d\n", packet_filter.t_protocal);
   printf("source port: %d\n", packet_filter.source_port);
   printf("destination port: %d\n", packet_filter.dest_port);
   printf("source ip: %s\n", packet_filter.source_ip);
   printf("destination ip: %s\n", packet_filter.dest_ip);
   printf("source interface: %s\n", packet_filter.source_if_name);
   printf("destination interface: %s\n", packet_filter.dest_if_name);
   printf("log file %s\n", log);

   if(strlen(log)==0){
    strcopy(log, "sniffer_log.txt");
   }
   log_file=fopen(log,"w");
   if(!log_file){
    exit_with_error("FAILED TO OPEN LOG FILE");
   }
   //37.56
    return 0;
}