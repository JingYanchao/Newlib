//
// Created by jyc on 17-3-16.
//

#ifndef MASTER_H
#define MASTER_H

#endif //MASTER_MASTER_H

#include <zconf.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <glib.h>

// atomic_int
#include <atomic>

//udp分发的个数，默认为4
int num_hash;

char MAC1[7]={(char) 0xe4, (char) 0xc7, 0x22, 0x3a, 0x60, (char) 0xb5};
char MAC2[7]={(char) 0x84, 0x78, (char) 0xac, 0x61, 0x22, (char) 0xf1};
char pcap_errbuf[1024];

//glib 错误变量
static GError *gerror = NULL;

pcap_t *desc = NULL;

struct pcap_stat stats;
struct bpf_program filter;

static std::atomic_int num_pro;
static GThreadPool *pool;

int linktype;
long long int inputstream_count = 0;
long long int outputstream_count = 0;

//pcap 超时时间
int pcap_timeout = 1024;

std::vector<Connection*> connect_list;
Connection* tcphdr_connection;
unsigned short tcphdr_port = 30001;
Connection* stream_connection;
unsigned short stream_port = 30002;
Connection* protocol_connection;
unsigned short protocol_port = 30003;

unsigned int init_port = 20788;

struct pcap_info
{
    int caplen;
    u_char * data;
    int link_offset;
};

