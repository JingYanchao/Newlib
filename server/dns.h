//
// Created by hadoop on 16-10-26.
//
#ifndef TEST_LIBNIDS_DNS_H
#define TEST_LIBNIDS_DNS_H
#include <string.h>
#include <arpa/inet.h>

using namespace std;

extern string dns_result;
extern string dns_back;

extern struct sockaddr_in server_addr3;
extern int client_socket_fd3;
extern struct sockaddr_in server_addr4;
extern int client_socket_fd4;

struct DnsHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct Dnsbody
{
    uint16_t type;
    uint16_t cls;
};

struct Dnsbody_response_part1
{
    uint16_t name;
    uint16_t type;
    uint16_t cls;
    uint16_t ttl1;

};

struct Dnsbody_response_part2
{
    uint16_t ttl2;
    uint16_t data_len;
};


struct ip_address
{
    unsigned int ip_addr;
};

void dns_parser_request(struct tuple4 *addr,  char  * buf,  int  len)
{
    int count=0;
    DnsHeader* dnsHeader = (DnsHeader*)buf;
    buf+=sizeof(DnsHeader);
    count+=sizeof(DnsHeader);
    if((ntohs(dnsHeader->flags)&0x8000)==0)
    {
        char num[30];
        sprintf(num, "%ld", time(0));
        dns_result.append(num);
        dns_result.append("\t");

        dns_result.append(inet_ntoa(*((struct in_addr*) &(addr->saddr))));
        dns_result.append("\t");

        dns_result.append(inet_ntoa(*((struct in_addr*) &(addr->daddr))));
        dns_result.append("\t");

        if(ntohs(dnsHeader->qdcount)==1)
        {

            char domainname[100]={0};
            u_int8_t i=0;
            while(*buf&&count<len&&count<98)
            {
                domainname[i]=*buf;
                if(*buf < 0x30)
                {
                    domainname[i]='.';
                }
                else
                {
                    domainname[i]=*buf;
                }
                buf++;
                count++;
                i++;
            }
            if(count==98)
                return;
            buf+=1;
            count++;
            if(domainname[0]==0||len-count<4)
            {
                return;
            }
            Dnsbody* dnsbody = (Dnsbody*)buf;
            dns_result.append(domainname);
            dns_result.append("\t");
            sprintf(num, "%d", ntohs(dnsbody->type));
            dns_result.append(num);
            dns_result.append("\t");
            sprintf(num, "%d", ntohs(dnsbody->cls));
            dns_result.append(num);
            dns_result.append("\n");
            if(sendto(client_socket_fd3, dns_result.c_str(), dns_result.length(),0,(struct sockaddr*)&server_addr3,sizeof(server_addr3)) < 0)
            {
                perror("Send Dns request data Failed:");
                exit(1);
            }
            return;
//                printf("%s\n",dns_result.c_str());
        }
        else
        {
            return;

        }

    }
    else
    {
        return;
    }
}

void dns_parser_response(struct tuple4 *addr,  char  * buf,  int  len)
{
    int count=0;
    DnsHeader* dnsHeader = (DnsHeader*)buf;
    buf+=sizeof(DnsHeader);
    count+=sizeof(DnsHeader);
    int numRRs = ntohs(dnsHeader->qdcount) + ntohs(dnsHeader->ancount) + ntohs(dnsHeader->nscount) + ntohs(dnsHeader->arcount);
    if((ntohs(dnsHeader->flags)&0x8000)!=0)
    {

//        char num[30];
//        sprintf(num, "%ld", time(0));
//        dns_back.append(num);
//        dns_result.append("\t");
//
//        dns_result.append(inet_ntoa(*((struct in_addr*) &(addr->saddr))));
//        dns_result.append("\t");
//
//        sprintf(num, "%d", addr->source);
//        dns_result.append(num);
//        dns_result.append("\t");
//
//        dns_result.append(inet_ntoa(*((struct in_addr*) &(addr->daddr))));
//        dns_result.append("\t");
//
//        sprintf(num, "%d", addr->dest);
//        dns_result.append(num);
        char domainname[100]={0};
        if(ntohs(dnsHeader->qdcount)==1)
        {


            u_int8_t i=0;
            while(*buf&&count<len&&count<98)
            {
                domainname[i]=*buf;
                if(*buf < 0x30)
                {
                    domainname[i]='.';
                }
                else
                {
                    domainname[i]=*buf;
                }
                buf++;
                count++;
                i++;
            }
            if(count==98)
                return;
            buf+=1;
            count++;
            if(domainname[0]==0||len-count<4)
            {
                return;
            }
//
            Dnsbody* dnsbody = (Dnsbody*)buf;
            buf += 4;
            count += 4;
//            dns_result.append(domainname);
//            dns_result.append("\t");
//            sprintf(num, "%d", ntohs(dnsbody->type));
//            dns_result.append(num);
//            dns_result.append("\t");
//            sprintf(num, "%d", ntohs(dnsbody->cls));
//            dns_result.append(num);
//            dns_result.append("\n");
//            if(sendto(client_socket_fd2, dns_result.c_str(), dns_result.length(),0,(struct sockaddr*)&server_addr2,sizeof(server_addr2)) < 0)
//            {
//                perror("Send File Name Failed:");
//                exit(1);
//            }
//            return;
//                printf("%s\n",dns_result.c_str());
        }
        else
        {
            return;

        }
        int num_ans = ntohs(dnsHeader->ancount);
//        printf("ans:%d\n",num_ans);
        while(num_ans>0)
        {
            if(len-count<12)
                return ;
            Dnsbody_response_part1* dnsbody_response = (Dnsbody_response_part1*) buf;
            buf += 8;
            Dnsbody_response_part2* dnsbody_response2 = (Dnsbody_response_part2*) buf;
            buf += 4;
            count+=12;
            if(dnsbody_response!=NULL&&dnsbody_response->type!=NULL&&ntohs(dnsbody_response->type)==1)
            {
//                printf("%d\n",sizeof(Dnsbody_response));
//                printf("len:%d\n",ntohs(dnsbody_response->data_len));
                ip_address* ip_address1 = (ip_address*)buf;
                buf+=4;
                count+=4;
                char num[30];
                sprintf(num, "%ld", time(0));
                dns_back.append(num);
                dns_back.append("\t");

                dns_back.append(inet_ntoa(*((struct in_addr*) &(addr->daddr))));
                dns_back.append("\t");

                dns_back.append(inet_ntoa(*((struct in_addr*) &(addr->saddr))));
                dns_back.append("\t");

                dns_back.append(domainname);
                dns_back.append("\t");

                sprintf(num, "%d", ntohs(dnsbody_response->type));
                dns_back.append(num);
                dns_back.append("\t");

                sprintf(num, "%d", ntohs(dnsbody_response->cls));
                dns_back.append(num);
                dns_back.append("\t");

                sprintf(num, "%d", ntohs(dnsbody_response2->ttl2));
                dns_back.append(num);
                dns_back.append("\t");

                dns_back.append(inet_ntoa(*((struct in_addr*) &(ip_address1->ip_addr))));
                dns_back.append("\n");
                if(sendto(client_socket_fd4, dns_back.c_str(), dns_back.length(),0,(struct sockaddr*)&server_addr4,sizeof(server_addr4)) < 0)
                {
                    perror("Send Dns response data Failed:");
                    exit(1);
                }
//                printf("%s",dns_back.c_str());

                dns_back.clear();
            }
            else
            {
                buf+=ntohs(dnsbody_response2->data_len);
                count+=ntohs(dnsbody_response2->data_len);
            }

            num_ans--;
        }
        return;

    }
    else
    {
        return;
    }
}

#endif //TEST_LIBNIDS_DNS_H
