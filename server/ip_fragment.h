#ifndef _NIDS_IP_FRAGMENT_H
#define _NIDS_IP_FRAGMENT_H

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3

void ip_frag_init(int);
void ip_frag_exit(void);
int ip_defrag_stub(struct ip *, struct ip **);

#endif
