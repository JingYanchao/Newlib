/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/
#ifndef _NIDS_TCP_H
#define _NIDS_TCP_H
#include <sys/time.h>

struct skbuff
{
//万年不变的next和prev，这向我们昭示了这是一个双向队列。
// 对于每个TCP会话（ip:端口<- ->ip:端口）都要维护两个skbuf队列（每个方向都有一个嘛）
// 每个skbuf对应网络上的一个IP包，TCP流就是一个接一个的IP包。
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;
  
  char fin;
  char urg;
  u_int seq;
  u_int ack;
};

int tcp_init(int);
void tcp_exit(void);
void process_tcp(u_char *, int);
void process_icmp(u_char *);
void tcp_check_timeouts(struct timeval *);

#endif /* _NIDS_TCP_H */
