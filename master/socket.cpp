//
// Created by jyc on 17-3-16.
//
#include "socket.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>

static void Socket(Connection* conn)
{
    int n;
    if((n = socket(AF_INET,SOCK_DGRAM, 0))<0)
    {
        perror("socket error");
    }
    conn->socket = n;
}

static void Address(Connection* conn, const char* ip_address, const unsigned short port)
{
    conn->server_addr.sin_family = AF_INET;
    conn->server_addr.sin_addr.s_addr = inet_addr(ip_address);
    conn->server_addr.sin_port = htons(port);
}

static Connection* get_connect(const char* ip_address, const unsigned short port)
{
    Connection* conn = (Connection*)malloc(sizeof(Connection));
    Socket(conn);
    Address(conn,ip_address,port);
    return conn;
}

void create_connect(int num,const char* ip_address, const unsigned short port,std::vector<Connection*>& connect_list)
{
    for(int i=port;i<port+num;i++)
        connect_list.push_back(get_connect(ip_address,i));
}

void init_connect(Connection* conn,const char* ip_address, const unsigned short port)
{
    Socket(conn);
    Address(conn,ip_address,port);
}

void Send(Connection* conn,u_char* send_data, size_t size)
{
    if(sendto(conn->socket, send_data, size,0,(struct sockaddr*)&conn->server_addr,sizeof(conn->server_addr)) < 0)
    {
        perror("Send File Name Failed1:");
    }
}

void destory_connect(std::vector<Connection*>& connect_list)
{
    for(auto s:connect_list)
        free(s);
}

