#include <stdio.h>
#include <stdint.h>
int utf16_to_utf8(const uint16_t *utf16, int utf16_len);
int utf8_to_utf16(const char *utf8, uint16_t *utf16);
uint16_t o[8]; 
int main(void){ int r,i; unsigned char *p=(unsigned char*)o;
 r=utf8_to_utf16("A\xc3\xa5\xe2\x82\xac\xf0\x9f\x98\x80",o); printf("%d",r); for(i=0;i<6;i++)printf(" %04x",o[i]); printf("\n");
 r=utf16_to_utf8(o,6); printf("%d",r); for(i=0;i<12;i++)printf(" %02x",p[i]); printf("\n");
 return 0;}
