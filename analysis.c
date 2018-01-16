#include "analysis.h"
#include "dispatch.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>

volatile unsigned long xmascount = 0;
volatile unsigned long arpcount = 0;
volatile unsigned long htmlcount = 0;
//Counts global due to sighandler being outside of this c file.
pthread_mutex_t mlGInt = PTHREAD_MUTEX_INITIALIZER;
//Global keeps consistency between threads.

void analyse(const unsigned char *packet,
             int verbose) {
//Takes packet and analyses based on spec.
  int i;
  unsigned char hasxmas = 0;
  unsigned char hasarp = 0;
  unsigned char hashtml = 0;
  //Has vals incremented seperate in analyse before collated at the end.
  //Avoids overusing the mutex lock throughout the function.
  struct tcphdr *tcphead;
  struct ip *iphead;
  unsigned char *packetpayload;

  //Identify that packet with our structs
  //printf("In Analyse\n");

  struct ether_header *ethhead = (struct ether_header *) packet;
  //printf("After packet parsed\n");
  const unsigned char *ethpayload = packet + ETH_HLEN;
  if (ntohs(ethhead->ether_type) == ETH_P_IP) {
    iphead = (struct ip *) ethpayload;
    const unsigned char *ippayload = packet + ETH_HLEN + iphead->ip_hl*4;
    if (iphead->ip_p == IPPROTO_TCP) {
      tcphead = (struct tcphdr *) ippayload;
      packetpayload = packet + ETH_HLEN + iphead->ip_hl * 4 + tcphead->doff * 4 ;
    }
  }
  //printf("After All Parse\n");
  //Start our XMAS scan if the packet is tcp.
  if (tcphead != NULL) {
    if (tcphead->urg && tcphead->psh && tcphead->fin) {
      hasxmas++;
      if (verbose) printf("XMAS FOUND\n");
    } else if (verbose) printf("XMAS NOT FOUND\n");
  }

  //Start our ARP search
  if (ntohs(ethhead->ether_type) == ETH_P_ARP) {
    hasarp++;
    if (verbose) printf("ARP FOUND\n");
  } else if (verbose) printf("ARP NOT FOUND\n");

  //Start our BLACKLIST scan if the port is 80 or 8080 ie html/htmls
  if (tcphead != NULL) {
    if (ntohs(tcphead->dest) == 80 || ntohs(tcphead->dest) == 8080) {
      unsigned char *substr = strstr(packetpayload, "Host:");
      if (substr != NULL)
        if (strstr(substr, "bbc.co.uk") != NULL) {
          hashtml++;
          if (verbose) printf("MALICIOUS HTML FOUND");
        } else if (verbose) printf("MALCIOUS HTML NOT FOUND");
    }
  }

  //Now add what we've done to the global vars.
  pthread_mutex_lock(&mlGInt);
    xmascount += hasxmas;
    htmlcount += hashtml;
    arpcount += hasarp;
  pthread_mutex_unlock(&mlGInt);
}
