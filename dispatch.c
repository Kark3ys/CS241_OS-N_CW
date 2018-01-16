#include "dispatch.h"
#include <pthread.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include "analysis.h"
#include "sniff.h"
#include "stack.h"

struct ststack * stack;
unsigned long pcount = 0;
char exitThreads = 0;

pthread_rwlock_t rwlPkt;
pthread_t rdThreads[THRCNT];

void initThreadStuff (void) {
//Run in sniff main func before anything else.
  pthread_rwlockattr_t attr;
  pthread_rwlockattr_init(&attr);
  pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
  //Make sure we're giving priority to writer or we get serious starvation.
  pthread_rwlock_init(&rwlPkt, &attr);
  pthread_rwlockattr_destroy(&attr);
  stack = malloc(sizeof(struct ststack));
  stack->head = NULL;
  exitThreads = 0;
  int i = 0;
  printf("Making Threads\n");
  for (i = 0; i < THRCNT; i++) {
    pthread_create(&rdThreads[i], NULL, &thread_code, NULL);
  }
}

void gracefulkill (int sig) {
//Sig handler, shitty name
  if (sig == SIGINT) {
    exitThreads++;  //Causes all running threads to finish off their while loop.
    void *rv;
    int i = 0;
    for (i=0; i<THRCNT; i++) pthread_join(rdThreads[i], &rv);
    //Means all threads finish what their doing with the current packet.
    printf("\nTOTAL PACKET COUNT %lu\n", pcount);
    printf("\nXMAS COUNT %lu\n", xmascount);
    printf("\nARP COUNT %lu\n", arpcount);
    printf("\nMALICIOUS HTML COUNT %lu\n", htmlcount);
    exit(EXIT_SUCCESS);
  }
}

void dispatch(u_char *args, const struct pcap_pkthdr *header,
              const unsigned char *packet) {
//Called by pcap_loop on each packet.
  pcount++;
  int verbose = (int) *args;
  //If we're running in verbose, we ain't doing threads.
  if (verbose) {
    dump(packet, header->len);
    analyse(packet, verbose);
  } else {
    pthread_rwlock_wrlock(&rwlPkt);
    push(stack, packet);
    //Reader threads automatically popping from stack.
    pthread_rwlock_unlock(&rwlPkt);
  }
}

void * thread_code (void* arg) {
//No args, we'll have to deal with stealing from the stack ourselves.
  static const int verbose = 0;
  //We know we aren't running in verbose mode but it keeps things consistent.
  unsigned char * pckt = NULL;
  signal(SIGINT,  gracefulkill);
  while (!exitThreads) {
    //While loop exits via signal handler "gracefullkill"
    pckt = NULL;
    if (stack->head){
    //No need to lock out stack for this check as two readers thinking it's ok
    //thanks to the locks.
      pthread_rwlock_rdlock(&rwlPkt);
      pckt = pop(stack);
      //NULL returned from empty stack.
      //printf("Popped from Stack\n");
      pthread_rwlock_unlock(&rwlPkt);

      //Actually analyse.
      if(pckt != NULL) {
        //printf("Analyse\n");
        analyse(pckt, verbose);
      }
    }
  }
}
