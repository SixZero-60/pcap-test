#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6


void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}


typedef struct {
   char* dev_;
} Param;

Param param  = {
   .dev_ = NULL
};


// extract structure(include/libnet/libnet-headers.h)
struct Ethernet_hdr
{
    u_char  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_char  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct Ipv4_hdr
{

    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct Tcp_hdr
{
    u_int16_t tcp_sport;       /* source port */
    u_int16_t tcp_dport;       /* destination port */
    u_int32_t tcp_seq;          /* sequence number */
    u_int32_t tcp_ack;          /* acknowledgement number */

    u_int8_t  tcp_flags;       /* control flags */

    u_int16_t tcp_win;         /* window */
    u_int16_t tcp_sum;         /* checksum */
    u_int16_t tcp_urp;         /* urgent pointer */
};


// whether TCP Packet
int IPROTOCOL_TCP(const u_char* packet){

   struct Ipv4_hdr* ip;
   packet = packet + sizeof(struct Ethernet_hdr);
   ip = (struct Ipv4_hdr*)packet;

   if(ip->ip_p == IPPROTO_TCP){
        printf("[Correct TCP Packet]");
      return 1;
   }
   else {
      return -1;
   }
}


bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

int main(int argc, char* argv[]) {
   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }


   while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
      printf("\n[%u bytes captured]\n", header->caplen);


            if(IPROTOCOL_TCP(packet) == 1){

            // Etherent Header
            struct Ethernet_hdr* eth = (struct Ethernet_hdr*)packet;
            packet = packet + sizeof(struct Ethernet_hdr);

            printf("\n-----------------------------------\n");
            printf("[Ethernet Header]\n");

            printf("MAC(source) => ");
            for(int i = 0; i<6; i++){
               printf("%02x:", eth->ether_shost[i]);
            }

            printf("\nMAC(destination) => ");
            for(int i = 0; i<6; i++){
               printf("%02x:", eth->ether_dhost[i]);
            }
            printf("\n\n");


            // Ipv4 Header
            struct Ipv4_hdr* Ip = (struct Ipv4_hdr*)packet;
            packet = packet + sizeof(struct Ipv4_hdr);

            printf("[IP Header]\n");
            printf("# IP(source) => %s\n", inet_ntoa(Ip->ip_src));
            printf("# IP(destination) => %s", inet_ntoa(Ip->ip_dst));

            printf("\n\n");


            // Tcp Header
            struct Tcp_hdr* tcp = (struct Tcp_hdr*)packet;
            packet = packet + sizeof(struct Tcp_hdr);

            printf("[TCP Header]\n");
            printf("# PORT(source) => %d\n", ntohs(tcp->tcp_sport));
            printf("# PORT(destination) => %d", ntohs(tcp->tcp_dport));

            printf("\n\n");


            // Payload(Data)
            printf("[Payload(Data)]\n");
            printf("# VALUE(hexadecimal) => ");

            for(int i=0; i<8; i++){
               printf("%02x ", *(packet+i));
            }
            printf("\n-----------------------------------\n");
            printf("\n");


            }

            else printf("[End]");
   }

   pcap_close(pcap);
}
