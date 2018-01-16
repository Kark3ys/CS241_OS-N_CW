#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H
#define THRCNT 10 //Some default value
#include <pcap.h>

extern char exitThreads;//If set, threads exit out of their while loops

void dispatch(u_char *args, const struct pcap_pkthdr *header,
              const unsigned char *packet);
void gracefulkill (int sig);
void initThreadStuff (void);
void * thread_code (void* arg);
#endif
