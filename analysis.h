#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H
extern volatile unsigned long xmascount;
extern volatile unsigned long arpcount;
extern volatile unsigned long htmlcount;

void analyse(const unsigned char *packet,
              int verbose);
#endif
