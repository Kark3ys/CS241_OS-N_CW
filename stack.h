struct element {
  struct element * next;
  unsigned char * pktptr; //Packet Pointer
};

struct ststack {
  struct element * head;
};

unsigned char * pop (struct ststack * stack);
void push (struct ststack * stack, unsigned char * ptr);
