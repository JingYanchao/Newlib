//
// Created by jyc on 16-11-4.
//
#include "http_parser.h"
#include "http_test.h"
#include "nids.h"
#include "dns.h"
#include "socketinterface.h"
#include <glib.h>


HttpParserSettings initObj;
HttpParser_response initObj_response;

string http_result;
string http_response;
string dns_result;
string dns_back;

static GAsyncQueue *tcp_queue;
static GAsyncQueue *response_queue;
static struct tcp_stream ERROR_item;

int method;
short server_port;

static void http_request_thread()
{
    tcp_stream *qitem;
    char temp_param[30];
    char temp_ip_address[30];
    struct half_stream *hlf;
    while(1)
    { /* loop "forever" */
        qitem=(tcp_stream *)g_async_queue_pop(tcp_queue);
        http_result.clear();
        /* EOF item received: we should exit */
        if (qitem==&ERROR_item)
        {
            printf("exit thread\n");
            break;
        }
        sprintf(temp_param, "%ld", time(0));
        http_result.append(temp_param);
        http_result.append("\t");

        sprintf(temp_param, "%d", qitem->server.count);
        http_result.append(temp_param);
        http_result.append("\t");

        inet_ntop(AF_INET,&(qitem->addr.saddr),temp_ip_address,30);
        http_result.append(temp_ip_address);
        http_result.append("\t");

        sprintf(temp_param, "%d", qitem->addr.source);
        http_result.append(temp_param);
        http_result.append("\t");

        inet_ntop(AF_INET,&(qitem->addr.daddr),temp_ip_address,30);
        http_result.append(temp_ip_address);
        http_result.append("\t");

        sprintf(temp_param, "%d", qitem->addr.dest);
        http_result.append(temp_param);

        http_parser *parser_request = (http_parser *)malloc(sizeof(http_parser));
        http_parser_init(parser_request, HTTP_REQUEST);

        size_t nparsed;         // 已经解析完成的数据大小
        hlf = &qitem->server;
        if(hlf->data[0]== 'G')
        {
            http_result.append("\t");
            http_result.append("G");
            method = 0;
        }
        else
        {
            http_result.append("\t");
            http_result.append("P");
            method = 1;
        }
        nparsed = http_parser_execute(parser_request, &ms_settings, hlf->data, (size_t) hlf->count);
        free(parser_request);
        free(hlf->data);
        free(qitem);
    }
    g_thread_exit(NULL);
}

static void http_response_thread()
{
    tcp_stream *qitem;
    char temp_param[30];
    char temp_ip_address[30];
    struct half_stream *hlf;
    while(1)
    { /* loop "forever" */
        qitem=(tcp_stream *)g_async_queue_pop(response_queue);
        http_response.clear();
        /* EOF item received: we should exit */
        if (qitem==&ERROR_item)
        {
            printf("exit thread\n");
            break;
        }
        sprintf(temp_param, "%ld", time(0));
        http_response.append(temp_param);
        http_response.append("\t");

        sprintf(temp_param, "%d", qitem->client.count);
        http_response.append(temp_param);
        http_response.append("\t");

        inet_ntop(AF_INET,&(qitem->addr.saddr),temp_ip_address,30);
        http_response.append(temp_ip_address);
        http_response.append("\t");

        sprintf(temp_param, "%d", qitem->addr.source);
        http_response.append(temp_param);
        http_response.append("\t");

        inet_ntop(AF_INET,&(qitem->addr.daddr),temp_ip_address,30);
        http_response.append(temp_ip_address);
        http_response.append("\t");

        sprintf(temp_param, "%d", qitem->addr.dest);
        http_response.append(temp_param);
        http_response.append("\t");

        hlf = &qitem->client;
        int i=0;
        if(hlf->data[0]=='H')
        {
            bzero(temp_param,sizeof(temp_param));
            while(hlf->data[i]!=' '&&hlf->data[i]!='\r\n')
            {
                i++;
            }
            while(hlf->data[i]==' ')
                i++;
            int j=0;
            while(hlf->data[i]!=' '&&hlf->data[i]!='\r\n')
            {
                temp_param[j++] = hlf->data[i++];
            }
            temp_param[j]='\0';
            http_response.append(temp_param);
            http_response.append("\t");
            http_parser *parser_response = (http_parser *)malloc(sizeof(http_parser));
            http_parser_init(parser_response, HTTP_RESPONSE);

            size_t nparsed;         // 已经解析完成的数据大小

            nparsed = http_parser_execute(parser_response, &ms_settings_response, hlf->data, (size_t) hlf->count);
            free(parser_response);
            free(hlf->data);
            free(qitem);
        }

    }
    g_thread_exit(NULL);
}

void udp_protocol_callback(struct tuple4 *addr,  char  * buf,  int  len)
{

    dns_result.clear();
    dns_back.clear();
    if(addr->dest == 53)
    {
        dns_parser_request(addr,buf,len);
    }
    else if(addr->source == 53)
    {
        dns_parser_response(addr,buf,len);
    }
    else
    {
        return ;
    }

}



void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    struct tuple4 ip_and_port = tcp_connection->addr;

    switch (tcp_connection->nids_state) /*Listen*/
    {

        case NIDS_JUST_EST:
            /*建立链接*/
            if(tcp_connection->addr.dest==80 || tcp_connection->addr.source==80)
            {

                tcp_connection->client.collect++;
                tcp_connection->server.collect++;
                tcp_connection->server.collect_urg++;
                tcp_connection->client.collect_urg++;
                //printf("%sTCP建立连接\n", address_string);
                return ;
            }
            else
            {
                return;
            }

        case NIDS_CLOSE:
            /*TCP连接正常关闭 */
        {
            if(tcp_connection->addr.dest==80)
            {

                if(tcp_connection->server.count)
                {
                    struct half_stream *hlf;
                    /* 表示服务器端接收数据*/
                    hlf = &tcp_connection->server;
                    /* hlf表示服务器端的数据*/
                    if(hlf->data[0] == 'P' ||hlf->data[0] == 'G')
                    {
//                    printf("%s",http_result.c_str());
                        if (hlf->count>0)
                        {
                            tcp_stream* tcp_s;
                            tcp_s = (tcp_stream*)malloc(sizeof(tcp_stream));
                            memmove(tcp_s,tcp_connection,sizeof(tcp_stream));
                            char *buf = (char*)malloc(2*sizeof(char)*(hlf->count));
                            memmove(buf, hlf->data, (size_t) hlf->count);
                            tcp_s->server.data = buf;
                            tcp_s->server.count = hlf->count;
                            g_async_queue_lock(tcp_queue);
                            /* ensure queue does not overflow */
                            if(g_async_queue_length_unlocked(tcp_queue) > 10000)
                            {
                                /* queue limit reached: drop packet - should we notify user via syslog? */
                                printf("drop the flow\n");

                            }
                            else
                            {
                                /* insert packet to queue */
                                g_async_queue_push_unlocked(tcp_queue,tcp_s);
                            }
                            g_async_queue_unlock(tcp_queue);
                        }
                    }
//                    printf("count:%d\n", hlf->count);
                    else
                    {
                        nids_discard(tcp_connection,0);
                    }
                }
                if (tcp_connection->client.count)
                {
                    struct half_stream *hlf;
                    /* 表示接收到新数据 */
                    hlf = &tcp_connection->client;
                    /* hlf表示客户端连接 */
                    if(hlf->data[0] == 'H')
                    {
                        if (hlf->count>0)
                        {
                            tcp_stream* tcp_s;
                            tcp_s = (tcp_stream*)malloc(sizeof(tcp_stream));
                            memmove(tcp_s,tcp_connection,sizeof(tcp_stream));
                            char *buf = (char*)malloc(2*sizeof(char)*(hlf->count));
                            memmove(buf, hlf->data, (size_t) hlf->count);
//                            printf("%s\n","yes");
                            tcp_s->client.data = buf;
                            tcp_s->client.count = hlf->count;
                            g_async_queue_lock(response_queue);
                            /* ensure queue does not overflow */
                            if(g_async_queue_length_unlocked(response_queue) > 10000)
                            {
                                /* queue limit reached: drop packet - should we notify user via syslog? */
                                printf("drop the flow\n");

                            }
                            else
                            {
                                /* insert packet to queue */
                                g_async_queue_push_unlocked(response_queue,tcp_s);
                            }
                            g_async_queue_unlock(response_queue);
                        }
                    }
                    else
                    {
                        nids_discard(tcp_connection,0);
                    }

                }
                return ;
            }
        }

        case NIDS_RESET:
            /* TCP被RST关闭 */
            return ;

        case NIDS_TIMED_OUT:
        {
            /* TCP超时 */
            string time_out_str;
            char saddr[30];
            sprintf(saddr,"%s",inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
            time_out_str.append(saddr);
            time_out_str.append("\t");
            char daddr[30];
            sprintf(daddr,"%s",inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
            time_out_str.append(daddr);
            time_out_str.append("\n");
            if(sendto(client_socket_fd5, time_out_str.c_str(), time_out_str.length(),0,(struct sockaddr*)&server_addr5,sizeof(server_addr5)) < 0)
            {
                perror("Send Dns response data Failed:");
                exit(1);
            }

            printf("%s %d %s %d\n", saddr,ip_and_port.source, daddr,ip_and_port.dest);
//           printf("%s %d %s %d\n",inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))),ip_and_port.source,inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))),ip_and_port.dest);
            return ;
        }

        case NIDS_DATA:
            /* 有数据到达 */
            return;
        default:
            break;
    }

    if (tcp_connection->server.count - tcp_connection->server.offset < 50)
    {
        // we haven't got enough data yet; keep all of it
        nids_discard (tcp_connection, 0);
        return;
    }
    return ;
}


void c_handle(int signum)
{
    printf("\nstop\n");
    nids_exit();
    exit(1);
}



int main(int argc, char** argv)
{
    //*******close the checksum******//
    struct nids_chksum_ctl temp;
    temp.netaddr = 0;
    temp.mask = 0;
    temp.action = 1;
    nids_register_chksum_ctl(&temp,1);

    //*******add statistic signal******//
    signal(SIGINT,c_handle);
    init_socket();
    if(argc!=2)
    {
        server_port = 20789;
    }
    else
    {
        server_port = (short) atoi(argv[1]);
    }

    nids_params.device = "eno2";

    if (!nids_init())
    {
        fprintf(stderr,"%s\n", nids_errbuf);
        exit(1);
    }

    tcp_queue = g_async_queue_new ();
    response_queue = g_async_queue_new();

    if(!(g_thread_new("http_request",(GThreadFunc)http_request_thread,(gpointer)(1))))
    {
        fprintf(stderr,"can not create thread");
        return 0;
    }
    if(!(g_thread_new("http_response",(GThreadFunc)http_response_thread,  (gpointer)(1))))
    {
        fprintf(stderr,"can not create thread");
        return 0;
    }

    nids_register_tcp((void *) tcp_protocol_callback);
    nids_register_udp((void *) udp_protocol_callback);
    nids_run();
    return 0;
}

