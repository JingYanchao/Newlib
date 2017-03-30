#include "libnids.h"
#include "checksum.h"
#include "ip_fragment.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"


#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

extern int ip_options_compile(unsigned char *);
//extern int raw_init();
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);

static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;

struct proc_node *tcp_procs;
static int linktype;

extern short server_port;

struct cap_queue_item
{
    void *data;
    bpf_u_int32 caplen;
};

/* marks end of queue */
static struct cap_queue_item EOF_item;
static struct udp_body EOF_udp_item;
static GError *gerror = NULL;


int sock;
//在recvfrom中使用的对方主机地址
struct sockaddr_in fromAddr;
struct sockaddr_in remoteAddr;
int recvLen;
unsigned int addrLen;
char recvBuffer[10000];

char nids_errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;
u_char *nids_last_pcap_data = NULL;
u_int nids_linkoffset = 0;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    300000,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
    NULL,			/* filename */
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    1,				/* multiproc */
    200000,			/* queue_limit */
    0,				/* tcp_workarounds */
    NULL,			/* pcap_desc */
    3600			/* tcp_flow_timeout */
};

static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR)
    {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	}
    else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;


    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

/* called either directly from pcap_hand() or from cap_queue_process_thread()
 * depending on the value of nids_params.multiproc - mcree
 */
static void call_ip_frag_procs(void *data,bpf_u_int32 caplen)
{
    struct proc_node *i;
    for (i = ip_frag_procs; i; i = i->next)
	(i->item) (data, caplen);
}


void nids_pcap_handler(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
    u_char *data_aligned;
    struct cap_queue_item *qitem;

    /*
     * Check for savagely closed TCP connections. Might
     * happen only when nids_params.tcp_workarounds is non-zero;
     * otherwise nids_tcp_timeouts is always NULL.
     */
    if (NULL != nids_tcp_timeouts)
      tcp_check_timeouts(&hdr->ts);

    nids_last_pcap_header = hdr;
    nids_last_pcap_data = data;
    (void)par; /* warnings... */
    switch (linktype)
    {
        case DLT_EN10MB:
        if (hdr->caplen < 14)
            return;
        /* Only handle IP packets and 802.1Q VLAN tagged packets below. */
        if (data[12] == 8 && data[13] == 0) {
            /* Regular ethernet */
            nids_linkoffset = 14;
        } else if (data[12] == 0x81 && data[13] == 0) {
            /* Skip 802.1Q VLAN and priority information */
            nids_linkoffset = 18;
        } else
            /* non-ip frame */
            return;
        break;
        default:
        break;
    }
    if (hdr->caplen < nids_linkoffset)
	return;

/*
* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
* handle->offset in pcap sources), so memcpy should not be called.
*/
#ifdef LBL_ALIGN
    if ((unsigned long) (data + nids_linkoffset) & 0x3)
    {
	data_aligned = alloca(hdr->caplen - nids_linkoffset + 4);
	data_aligned -= (unsigned long) data_aligned % 4;
	memmove(data_aligned, data + nids_linkoffset, hdr->caplen - nids_linkoffset);
    } else 
#endif
  data_aligned = data + nids_linkoffset;

    if(nids_params.multiproc)
    {
        /* 
         * Insert received fragment into the async capture queue.
         * We hope that the overhead of memcpy 
         * will be saturated by the benefits of SMP - mcree
         */
        qitem=malloc(sizeof(struct cap_queue_item));
        if (qitem && (qitem->data=malloc(hdr->caplen - nids_linkoffset)))
        {
          qitem->caplen=hdr->caplen - nids_linkoffset;
          memmove(qitem->data,data_aligned,qitem->caplen);
          g_async_queue_lock(cap_queue);
          /* ensure queue does not overflow */
          if(g_async_queue_length_unlocked(cap_queue) > nids_params.queue_limit)
          {
            /* queue limit reached: drop packet - should we notify user via syslog? */
            free(qitem->data);
            free(qitem);
          } else {
            /* insert packet to queue */
//              printf("%d\n",g_async_queue_length_unlocked(cap_queue));
            g_async_queue_push_unlocked(cap_queue,qitem);
          }
          g_async_queue_unlock(cap_queue);
	    }
    }
    else
    { /* user requested simple passthru - no threading */
        call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
    }
}

static void gen_ip_frag_proc(u_char * data, int len)
{
    struct proc_node *i;
    struct ip *iph = (struct ip *) data;
    int need_free = 0;
    int skblen;
    void (*glibc_syslog_h_workaround)(int, int, struct ip *, void*)=
        nids_params.syslog;

    if (!nids_params.ip_filter(iph, len))
	return;

    if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
	return;
    }
    if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
	glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
	return;
    }
    switch (ip_defrag_stub((struct ip *) data, &iph)) {
    case IPF_ISF:
	return;
    case IPF_NOTF:
	need_free = 0;
	iph = (struct ip *) data;
	break;
    case IPF_NEW:
	need_free = 1;
	break;
    default:;
    }
    skblen = ntohs(iph->ip_len) + 16;
    if (!need_free)
	skblen += nids_params.dev_addon;
    skblen = (skblen + 15) & ~15;
    skblen += nids_params.sk_buff_size;

    for (i = ip_procs; i; i = i->next)
	(i->item) (iph, skblen);
    if (need_free)
	free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	    return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
    if (udph->uh_sum && my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    struct udp_body* udpby;
    udpby = (struct udp_body*)malloc(sizeof(struct udp_body));
    udpby->addr =  addr;
    udpby->buf = (char*)malloc((ulen - sizeof(struct udphdr)));
    memmove(udpby->buf,((char*)udph) + sizeof(struct udphdr),ulen-sizeof(struct udphdr));
    udpby->len = ulen - sizeof(struct udphdr);
    g_async_queue_lock(udp_queue);
    /* ensure queue does not overflow */
    if(g_async_queue_length_unlocked(udp_queue) > 10000)
    {
        /* queue limit reached: drop packet - should we notify user via syslog? */
        printf("drop the flow\n");
        exit(1);
    }
    else
    {
        /* insert packet to queue */
        g_async_queue_push_unlocked(udp_queue,udpby);
    }
    g_async_queue_unlock(udp_queue);


}



static void gen_ip_proc(u_char * data, int skblen)
{

    switch (((struct ip *) data)->ip_p) {
    case IPPROTO_TCP:
	process_tcp(data, skblen);
	break;
    case IPPROTO_UDP:
	process_udp((char *)data);
	break;
    case IPPROTO_ICMP:
	if (nids_params.n_tcp_streams)
	    process_icmp(data);
	break;
    default:
	break;
    }
}



static void init_procs()
{
    ip_frag_procs = mknew(struct proc_node);
    ip_frag_procs->item = gen_ip_frag_proc;
    ip_frag_procs->next = 0;
    ip_procs = mknew(struct proc_node);
    ip_procs->item = gen_ip_proc;
    ip_procs->next = 0;
    tcp_procs = 0;
    udp_procs = 0;
}

void nids_register_udp(void (*x))
{
    register_callback(&udp_procs, x);
}

void nids_unregister_udp(void (*x))
{
    unregister_callback(&udp_procs, x);
}

void nids_register_ip(void (*x))
{
    register_callback(&ip_procs, x);
}

void nids_unregister_ip(void (*x))
{
    unregister_callback(&ip_procs, x);
}

void nids_register_ip_frag(void (*x))
{
    register_callback(&ip_frag_procs, x);
}

void nids_unregister_ip_frag(void (*x))
{
    unregister_callback(&ip_frag_procs, x);
}


static void cap_queue_process_thread()
{
    struct cap_queue_item *qitem;

    while(1) { /* loop "forever" */
        qitem=g_async_queue_pop(cap_queue);
//        printf("%d %d\n",strlen(qitem->data),qitem->caplen);
        if (qitem==&EOF_item) break; /* EOF item received: we should exit */
        call_ip_frag_procs(qitem->data,qitem->caplen);
        free(qitem->data);
        free(qitem);
    }
    g_thread_exit(NULL);
}

static udp_queue_process_thread()
{

    struct udp_body* udp_item;
    while(1)
    {
        udp_item =(struct udp_body*)g_async_queue_pop(udp_queue);

        struct proc_node *ipp = udp_procs;
//        printf("%d %d\n",udp_item->len,strlen(udp_item->buf));
        if (udp_item==&EOF_udp_item)
        {
            printf("exit thread\n");
            break;
        }
        while(ipp)
        {
            ipp->item(&udp_item->addr, udp_item->buf,
                      udp_item->len);
            ipp = ipp->next;
        }
        free(udp_item->buf);
        free(udp_item);

    }
    g_thread_exit(NULL);
}


int static START_CAP_QUEUE_PROCESS_THREAD()
{
    printf("Thread start\n");
    if(nids_params.multiproc)
    {
        if(!(g_thread_new("ip_cap",(GThreadFunc)cap_queue_process_thread, (gpointer)(1)))) {
            strcpy(nids_errbuf, "thread: ");
            strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8);
            return 0;
        }
    }
}

int static START_UDP_QUEUE_PROCESS_THREAD()
{
    printf("Thread start\n");
    if(nids_params.multiproc)
    {
        if(!(g_thread_new("udp_cap",(GThreadFunc)udp_queue_process_thread, (gpointer)(1))))
        {
            strcpy(nids_errbuf, "thread: ");
            strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8);
            return 0;
        }
    }
}

int static STOP_CAP_QUEUE_PROCESS_THREAD()
{
    if(nids_params.multiproc)
    { /* stop the capture process thread */
        g_async_queue_push(cap_queue,&EOF_item);
    }
}

int static STOP_UDP_QUEUE_PROCESS_THREAD()
{
    if(nids_params.multiproc)
    { /* stop the capture process thread */
        g_async_queue_push(udp_queue,&EOF_udp_item);
    }
}


/* thread entry point 
 * pops capture queue items and feeds them to
 * the ip fragment processors - mcree
 */

int nids_init()
{
    linktype = DLT_EN10MB;
    if (nids_params.dev_addon == -1)
    {
        if (linktype == DLT_EN10MB)
            nids_params.dev_addon = 16;
        else
            nids_params.dev_addon = 0;
    }
    nids_linkoffset=14;
    if (nids_params.syslog == nids_syslog)
	openlog("libnids", 0, LOG_LOCAL0);
    init_procs();
    tcp_init(nids_params.n_tcp_streams);
    ip_frag_init(nids_params.n_hosts);

    if(nids_params.multiproc)
    {
         cap_queue=g_async_queue_new();
         udp_queue = g_async_queue_new();
    }

    return 1;
}

int init_socket()
{
    memset(&fromAddr,0,sizeof(fromAddr));
    fromAddr.sin_family=AF_INET;
    fromAddr.sin_addr.s_addr=htonl(INADDR_ANY);
    fromAddr.sin_port = htons(server_port);
    sock = socket(AF_INET,SOCK_DGRAM,0);
    if(sock < 0)
    {
        printf("create sock failed.\r\n");
        exit(0);
    }
    if(bind(sock,(struct sockaddr*)&fromAddr,sizeof(fromAddr))<0)
    {
        fprintf(stderr, "bind failed\n");
        close(sock);
        exit(1);
    }
}

int socket_recv()
{
    int addrLens = sizeof(struct sockaddr);
    if((recvLen = recvfrom(sock,recvBuffer,10000,0,(struct sockaddr*)&remoteAddr,&addrLens))<0)
    {
        fprintf(stderr, "recvfailed\n");
        close(sock);
        exit(1);
    }
    return recvLen;
}
int nids_run()
{
    init_socket();
    START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
    START_UDP_QUEUE_PROCESS_THREAD();

    while(1)
    {
        int len = socket_recv();
        u_char* prm ="";
        struct pcap_pkthdr* hrd = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr*));
        hrd->caplen=len;
        hrd->len = len;
        u_char* data = (u_char*)malloc(len+1);
        memmove(data,recvBuffer,len);
        gettimeofday(&hrd->ts, NULL);
        nids_pcap_handler("",hrd,data);
        free(hrd);
        free(data);
    }
    STOP_CAP_QUEUE_PROCESS_THREAD();
    STOP_UDP_QUEUE_PROCESS_THREAD();
    nids_exit();
    return 0;
}

void nids_exit()
{

    if (nids_params.multiproc)
    {
    /* I have no portable sys_sched_yield,
       and I don't want to add more synchronization...
    */
      while (g_async_queue_length(cap_queue)>0)
        usleep(100000);
    }
    tcp_exit();
    ip_frag_exit();
    free(ip_procs);
    free(ip_frag_procs);
}

