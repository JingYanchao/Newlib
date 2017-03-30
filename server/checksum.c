#include "nids.h"

static struct nids_chksum_ctl * nchk;
static int nrnochksum=0;

void nids_register_chksum_ctl(struct nids_chksum_ctl * ptr, int nr)
{
	nchk=ptr;
	nrnochksum=nr;
}

static int dontchksum(unsigned int ip)
{
	int i;
		for (i=0;i<nrnochksum;i++)
			if ((ip & nchk[i].mask)==nchk[i].netaddr)
				return nchk[i].action;
	return 0;
}


struct psuedo_hdr
{
  u_int saddr;      
  u_int daddr;      
  u_char zero;        
  u_char protocol;    
  u_short len;        
};

u_short
ip_check_ext(register u_short *addr, register int len, int addon)
{
  register int nleft = len;
  register u_short *w = addr;
  register int sum = addon;
  u_short answer = 0;

  /*
   *  Our algorithm is simple, using a 32 bit accumulator (sum),
   *  we add sequential 16 bit words to it, and at the end, fold
   *  back all the carry bits from the top 16 bits into the lower
   *  16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }
  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *)w;
    sum += answer;
  }  
  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;                          /* truncate to 16 bits */
  return (answer);
}

u_short
ip_fast_csum(u_short *addr, int len)
{
  if (dontchksum(((struct ip*)addr)->ip_src.s_addr))
	return 0;
  return ip_check_ext(addr, len << 2, 0);
}

u_short
ip_compute_csum(u_short *addr, int len)
{
  return ip_check_ext(addr, len, 0);
}

u_short
my_tcp_check(struct tcphdr *th, int len, u_int saddr, u_int daddr)
{
  unsigned int i;
  int sum = 0;
  struct psuedo_hdr hdr;

  if (dontchksum(saddr))
  	return 0;
  
  hdr.saddr = saddr;
  hdr.daddr = daddr;
  hdr.zero = 0;
  hdr.protocol = IPPROTO_TCP;
  hdr.len = htons(len);
  for (i = 0; i < sizeof(hdr); i += 2)
    sum += *(u_short *)((char *)(&hdr) + i);
  
  return (ip_check_ext((u_short *)th, len, sum));
}                     
u_short
my_udp_check(void *u, int len, u_int saddr, u_int daddr)
{
   unsigned int i;
   int sum = 0;
   struct psuedo_hdr hdr;

   if (dontchksum(saddr))
  	 return 0;

   hdr.saddr = saddr;
   hdr.daddr = daddr;
   hdr.zero = 0;
   hdr.protocol = IPPROTO_UDP;
   hdr.len = htons(len);
   for (i = 0; i < sizeof(hdr); i += 2)
     sum += *(u_short *)((char *)(&hdr) + i);

   return (ip_check_ext((u_short *)u, len, sum));
}
