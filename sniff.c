#include "sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "dispatch.h"


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  //Let's make some of that thread shit first.
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  //Start thread pool.
  if (!verbose) {
    initThreadStuff();
    printf("Init Thread Stuff\n");
  } else {
    //All the printfs mess with threads and pcap_loop for delays.
    printf("No Thread Mode\n");
  }
  signal(SIGINT,  gracefulkill);
  pcap_loop(pcap_handle, -1, (pcap_handler) dispatch, (u_char *) &verbose);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  signal(SIGINT,  gracefulkill);
  printf("\nType: %04hx\n", ntohs(eth_header->ether_type));

  if (ntohs(eth_header->ether_type) == ETH_P_IP) {
    const unsigned char *ethpayload = data + ETH_HLEN;
    struct ip *iphead = (struct ip *) ethpayload;
    printf(" === IP HEADER === \n");
    //printf("Ver: %hhu\n", iphead->ip_v);
    //printf("HL: %hhu\n", iphead->ip_hl);
    printf("ToS: %hhu\n", iphead->ip_tos);
    printf("Len: %hu\n", iphead->ip_len);
    printf("ID: %hu\n", ntohs(iphead->ip_id));
    printf("Frag: %hu\n", ntohs(iphead->ip_off));
    printf("TtL: %hhu\n", iphead->ip_ttl);
    printf("Prot: %hhu\n", iphead->ip_p); //https://tools.ietf.org/html/rfc790
    //printf("HCS: %hu\n", iphead->ip_sum);
    char chrTempIP = 0;
    printf("SRC: ");
    for (i = 3; i >= 0; i--) {
      chrTempIP = ((ntohl(iphead->ip_src.s_addr)) >> (i << 3)) & 0xff;
      printf("%hhu", chrTempIP);
      if (i > 0) printf(":");
    }
    printf("\n");
    printf("DST: ");
    for (i = 3; i >= 0; i--) {
      chrTempIP = ((ntohl(iphead->ip_dst.s_addr)) >> (i << 3)) & 0xff;
      printf("%hhu", chrTempIP);
      if (i > 0) printf(":");
    }
    printf("\n");

    const unsigned char *ippayload = data + ETH_HLEN + iphead->ip_hl*4;

    if (iphead->ip_p == IPPROTO_TCP) {
      struct tcphdr *tcphead = (struct tcphdr *) ippayload;
      printf(" === TCP HEADER === \n");
      printf("SrcPort: %u\n", ntohs(tcphead->source));
      printf("DstPort: %u\n", ntohs(tcphead->dest));
      printf("Seq Num: %lu\n", ntohl(tcphead->seq));
      printf("Ack Num: %lu\n", ntohl(tcphead->ack_seq));
      //printf("Offset: %u\n", tcphead->doff);
      //printf("Window: %u\n", tcphead->window);
      //printf("Checksum: %u\n", tcphead->check);
      printf("UrgPtr: %u\n", ntohs(tcphead->urg_ptr));
      printf("Flags:\n");
      printf("URG|ACK|PSH|RST|SYN|FIN\n");
      printf("[%u]|[%u]|[%u]|[%u]|[%u]|[%u]\n",
        tcphead->urg, tcphead->ack, tcphead->psh,
        tcphead->rst, tcphead->syn, tcphead->fin);

      printf(" === PACKET %ld DATA == \n", pcount);
      // Decode Packet Data (Skipping over the header)
      int data_bytes = length - ETH_HLEN - iphead->ip_hl * 4 - tcphead->doff * 4;
      const unsigned char *packetpayload = data + ETH_HLEN + iphead->ip_hl * 4 + tcphead->doff * 4 ;
      const static int output_sz = 20; // Output this many bytes at a time
      while (data_bytes > 0) {
        int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
        // Print data in raw hexadecimal form
        for (i = 0; i < output_sz; ++i) {
          if (i < output_bytes) {
            printf("%02x ", packetpayload[i]);
          } else {
            printf ("   "); // Maintain padding for partial lines
          }
        }
        printf ("\b|");
        // Print data in ascii form
        for (i = 0; i < output_bytes; ++i) {
          char byte = packetpayload[i];
          if (byte > 31 && byte < 127) {
            // Byte is in printable ascii range
            printf("%c", byte);
          } else {
            printf(".");
          }
        }
        printf("\n");
        packetpayload += output_bytes;
        data_bytes -= output_bytes;
      }
    } else if (iphead->ip_p == 1) {
      //Do your ICMP shit
      printf("ICPM: TYPE: %hhu", ippayload[0]);
    } else {
      printf("Not gonna touch that IP protocol.\n");
    }
  } else if (ntohs(eth_header->ether_type) == ETH_P_ARP) {
    printf("INSERT ARP STUFF\n");
  } else {
    printf("Not gonna touch that ethernet type.\n");
  }

  ++pcount;
}
