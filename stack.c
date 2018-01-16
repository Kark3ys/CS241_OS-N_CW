//Stack Implementation is altered from Lab 2 Linked List Design
#include <stdlib.h>
#include "stack.h"
unsigned char * pop (struct ststack * stack) {
  struct element * elem = stack->head;
  if (elem) {
    unsigned char * result = elem->pktptr;
    stack->head = elem->next;
    free(elem);
    return result;
  } else {
    return NULL;
  }
}

void push (struct ststack * stack, unsigned char * ptr) {
  struct element * elem = malloc(sizeof(struct element));
  elem->pktptr = ptr;
  elem->next = stack->head;
  stack->head = elem;
}
