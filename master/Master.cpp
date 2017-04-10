//
// Created by jyc on 17-3-16.
//
#include "socket.h"
#include "Protocol.h"
#include "hash.h"
#include "Master.h"
#include <string>
using namespace std;
volatile int alarm_flag = 0;
void tcp_protocol_statistic(unsigned short port)
{
    switch(ntohs(port))
    {
        case 25:
        {
            num_smtp+=1;
            num_total+=1;
            break;
        }
        case 110:
        {
            num_pop3+=1;
            num_total+=1;
            break;
        }
        case 80:
        {
            num_http+=1;
            num_total+=1;
            break;
        }
        case 443:
        {
            num_https+=1;
            num_total+=1;
            break;
        }
        case 23:
        {
            num_telnet+=1;
            num_total+=1;
            break;
        }
        case 20:
        {
            num_ftp+=1;
            num_total+=1;
            break;
        }
        case 21:
        {
            num_ftp+=1;
            num_total+=1;
            break;
        }
        default:
        {

        }
    }
}

void udp_protocol_statistic(unsigned short port)
{
    switch(ntohs(port))
    {
        case 53:
        {
            num_dns+=1;
            num_total+=1;
            break;
        }
        default:
        {

        }
    }
}

void tcp_header_send(ip_header* ip_hdr,tcp_header* tcp_hdr)
{
    char buf[20];
    string tcp_info;
    inet_ntop(AF_INET,&(ip_hdr->src),buf,30);
    tcp_info.append(buf);
    tcp_info.append("\t");
    inet_ntop(AF_INET,&(ip_hdr->dst),buf,30);
    tcp_info.append(buf);
    tcp_info.append("\t");
    sprintf(buf,"%d",htons(tcp_hdr->sport));
    tcp_info.append(buf);
    tcp_info.append("\t");
    sprintf(buf,"%d",htons(tcp_hdr->dport));
    tcp_info.append(buf);
    tcp_info.append("\t");
    sprintf(buf,"%d",tcp_hdr->flags);
    tcp_info.append(buf);
    tcp_info.append("\n");
    Send(tcphdr_connection, (u_char *) tcp_info.c_str(), tcp_info.size());
}

void stream_send()
{
    string stream_info;
    char buf[30];
    sprintf(buf,"%lld",inputstream_count/1000);
    stream_info.append(buf);
    stream_info.append("\t");
    sprintf(buf,"%lld",outputstream_count/1000);
    stream_info.append(buf);
    stream_info.append("\n");
    Send(stream_connection,(u_char*)stream_info.c_str(),stream_info.size());
    inputstream_count = 0;
    outputstream_count = 0;
}

void Protocol_send()
{
    string Protocol_info;
    char buf[20];
    sprintf(buf,"%d",num_dns);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_smtp);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_pop3);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_http);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_https);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_telnet);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_ftp);
    Protocol_info.append(buf);
    Protocol_info.append("\t");
    sprintf(buf,"%d",num_total);
    Protocol_info.append(buf);
    Protocol_info.append("\n");
    Send(protocol_connection,(u_char*)Protocol_info.c_str(),Protocol_info.size());
    num_dns = 0;
    num_smtp = 0;
    num_pop3 = 0;
    num_http = 0;
    num_https = 0;
    num_telnet = 0;
    num_ftp = 0;
    num_total = 0;
}


int mac_cmp(char* mac_array)
{
    int flag = 1;
    for(int i=0;i<6;i++)
    {
        if(mac_array[i] != MAC1[i])
        {
            flag = 0;
        }
    }
    if(flag!=0)
        return flag;
    flag = 2;
    for(int i=0;i<6;i++)
    {
        if(mac_array[i] != MAC2[i])
            flag = 0;
    }
    return flag;
}

void pcap_exit()
{
    if (desc!=NULL)
        pcap_close(desc);
    desc = NULL;
}

int open_live(char* dev)
{
    pcap_exit();
    char *device;
    int promisc = 0;
    printf("%s\n",dev);
    if (dev == NULL)
        fprintf(stderr, "the device is empty");

    device = dev;
    if (!strcmp(device, "all"))
        device = (char *) "any";
    if ((desc = pcap_open_live(device, 16384, 1, pcap_timeout, pcap_errbuf)) == NULL)
    {
        fprintf(stderr, "open device failed");
        exit(1);
    }
    else
    {
        printf("open device success\n");
        return 1;
    }
}



static void process_packet(gpointer data,gpointer user_data)
{
    struct pcap_info* qitem;
    qitem = (struct pcap_info *) data;
    /* EOF item received: we should exit */
    num_pro++;
    u_char* copy_data = qitem->data;
    qitem->data+=qitem->link_offset;
    ip_header* iphdr = (ip_header*)qitem->data;
    qitem->data+=sizeof(ip_header);
    if(iphdr->prot == 6)//TCP
    {

        tcp_header* tcp_hdr = (tcp_header* )qitem->data;
        tcp_protocol_statistic(tcp_hdr->dport);
        tcp_protocol_statistic(tcp_hdr->sport);
        tcp_header_send(iphdr,tcp_hdr);
        u_int res=mkhash(iphdr->src.s_addr,tcp_hdr->sport,iphdr->dst.s_addr,tcp_hdr->dport);
        Send(connect_list[res%num_hash],copy_data,qitem->caplen);
    }
    else if(iphdr->prot ==17)//UDP
    {
        udp_header* udp_hdr = (udp_header* )qitem->data;
        udp_protocol_statistic(udp_hdr->dport);
        udp_protocol_statistic(udp_hdr->sport);
        u_int res=mkhash(iphdr->src.s_addr,udp_hdr->sport,iphdr->dst.s_addr,udp_hdr->dport);
        Send(connect_list[res%num_hash],copy_data,qitem->caplen);
    }
    free(copy_data);
    free(qitem);

}


void pcap_func(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
    int link_offset;
    //judge the linktype then compute the ethernet offset
    switch (linktype)
    {
        case DLT_EN10MB:
            if (hdr->caplen < 14)
                return;
            /* Only handle IP packets and 802.1Q VLAN tagged packets below. */
            if (data[12] == 8 && data[13] == 0)
            {
                /* Regular ethernet */
                link_offset = 14;
            }
            else if (data[12] == 0x81 && data[13] == 0)
            {
                /* Skip 802.1Q VLAN and priority information */
                link_offset = 18;
            }
            else
                /* non-ip frame */
                return;
            break;\
        case DLT_PRISM_HEADER:
            link_offset = 144; //sizeof(prism2_hdr);
            break;
        default:
            link_offset = 18;
    }
    pcap_info* info;

    //copy the raw data
    info = (pcap_info*)malloc(sizeof(pcap_info));
    info->caplen = hdr->caplen;
    info->link_offset = link_offset;
    info->data = (u_char *)malloc(sizeof(u_char)*(hdr->caplen));
    memmove(info->data,data,hdr->caplen);
    mac_header* machdr = (mac_header*)info->data;

    //统计入口和出口的流量
    int cmp_res = mac_cmp(machdr->m_cDstMacAddress);
    if(cmp_res ==1)
    {
        inputstream_count+=info->caplen;
    }
    else
    {
        outputstream_count+=info->caplen;
    }
    if(alarm_flag==1)
    {
        stream_send();
        Protocol_send();
        alarm_flag = 0;
        alarm(1);
    }

    //push the copy data into thread pool queue
    g_thread_pool_push(pool, (gpointer *)info , NULL);

}

int pcap_run()
{
    if (!desc)
    {
        fprintf(stderr, "pcap not initialized");
        return 0;
    }
    linktype = pcap_datalink(desc);
    pcap_loop(desc, -1, (pcap_handler) pcap_func, 0);
    return 1;
}


int filter_set(char* str)
{
    if(str!=NULL)
    {
        if(pcap_compile(desc, &filter, str, 1, 0)<0)
        {
            return 0;
        }
        if(pcap_setfilter(desc, &filter) == -1)
        {
            return 0;
        }
    }
    return 1;
}

void start_pcap_thread()
{
    pool = g_thread_pool_new(process_packet,NULL,-1,FALSE,&gerror);
}


void c_handle(int signum)
{
    pcap_stats(desc,&stats);
    printf("\nRecieved packets:%d\n",stats.ps_recv);
    printf("Dropped by kernel:%d\n",stats.ps_drop);
    printf("Dropped by filter:%d\n",stats.ps_ifdrop);
    printf("processed by thread:%d\n", static_cast<int>(num_pro));
    printf("the total inputstream_count:%lld\n",inputstream_count);
    printf("the total outputstream_count:%lld\n",outputstream_count);
    printf("DNS:%d,SMTP:%d,POP3:%d,HTTP:%d,HTTPS：%d,TELNET:%d,FTP:%d\n",num_dns,num_smtp,num_pop3,num_http,num_https,num_telnet,num_ftp);
    pcap_exit();
    exit(1);
}

void c_statistic(int signum)
{
   alarm_flag = 1;
}

void init_socket()
{
    create_connect(num_hash,"127.0.0.1",init_port,connect_list);
    tcphdr_connection = (Connection*)malloc(sizeof(Connection));
    init_connect(tcphdr_connection,"10.255.0.12",tcphdr_port);
    stream_connection = (Connection*)malloc(sizeof(Connection));
    init_connect(stream_connection,"224.0.0.1",stream_port);
    protocol_connection = (Connection*)malloc(sizeof(Connection));
    init_connect(protocol_connection,"10.255.0.12",protocol_port);
}

int main(int argc,char *argv[])
{
    char* dev;
    if(argc == 1)
    {
        dev = "any";
        num_hash = 4;
    }
    else if(argc == 2)
    {
        dev = argv[1];
        num_hash = 4;
    }
    else if(argc == 3)
    {
        dev = argv[1];
        num_hash = atoi(argv[2]);
        printf("the hash_num is %d\n",num_hash);
    }
    pool = NULL;
    alarm(1);
    signal(SIGINT,c_handle);
    signal(SIGALRM,c_statistic);
    num_pro = 0;
    open_live(dev);
    init_hash();
    filter_set("ip");
    init_socket();
    start_pcap_thread();
    linktype = pcap_datalink(desc);
    pcap_run();
}



