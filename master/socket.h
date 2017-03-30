//
// Created by jyc on 17-3-16.
//

#ifndef SOCKET_H
#define SOCKET_H

#endif //MASTER_SOCKET_H
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <vector>

struct Connection
{
    int socket;
    sockaddr_in server_addr;
    unsigned short port;
};

static void Socket(Connection* conn);
static void Address(Connection* conn, const char* ip_address, const unsigned short port);
static Connection* get_connect(const char* ip_address, const unsigned short port);
void Send(Connection* conn,u_char* send_data, size_t size);
void create_connect(int num,const char* ip_address,const unsigned short port,std::vector<Connection*>& connect_list);
void init_connect(Connection* conn,const char* ip_address, const unsigned short port);
void destroy(std::vector<Connection*>& connect_list);
