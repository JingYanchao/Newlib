//
// Created by jyc on 16-11-18.
//
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef NEWLIBS_SOCKETINTERFACE_H
#define NEWLIBS_SOCKETINTERFACE_H

#define SERVER_PORT 10666  //http request
#define SERVER_PORT2 10667 //http response
#define SERVER_PORT3 10668 //dns request
#define SERVER_PORT4 10669 //dns response
#define SERVER_PORT5 10672 //tcp time out


struct sockaddr_in server_addr;
int client_socket_fd;
struct sockaddr_in server_addr2;
int client_socket_fd2;
struct sockaddr_in server_addr3;
int client_socket_fd3;
struct sockaddr_in server_addr4;
int client_socket_fd4;
struct sockaddr_in server_addr5;
int client_socket_fd5;

void init_socket()
{
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("10.255.0.12");
    server_addr.sin_port = htons(SERVER_PORT);

    /* 创建socket */
    client_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_socket_fd < 0)
    {
        perror("Create Socket1 Failed:");
        exit(1);
    }

    bzero(&server_addr2, sizeof(server_addr2));
    server_addr2.sin_family = AF_INET;
    server_addr2.sin_addr.s_addr = inet_addr("10.255.0.12");
    server_addr2.sin_port = htons(SERVER_PORT2);

    /* 创建socket */
    client_socket_fd2 = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_socket_fd2 < 0)
    {
        perror("Create Socket2 Failed:");
        exit(1);
    }

    bzero(&server_addr3, sizeof(server_addr3));
    server_addr3.sin_family = AF_INET;
    server_addr3.sin_addr.s_addr = inet_addr("10.255.0.12");
    server_addr3.sin_port = htons(SERVER_PORT3);

    /* 创建socket */
    client_socket_fd3 = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_socket_fd3 < 0)
    {
        perror("Create Socket3 Failed:");
        exit(1);
    }

    bzero(&server_addr4, sizeof(server_addr4));
    server_addr4.sin_family = AF_INET;
    server_addr4.sin_addr.s_addr = inet_addr("10.255.0.12");
    server_addr4.sin_port = htons(SERVER_PORT4);

    /* 创建socket */
    client_socket_fd4 = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_socket_fd4 < 0)
    {
        perror("Create Socket4 Failed:");
        exit(1);
    }

    bzero(&server_addr5, sizeof(server_addr5));
    server_addr5.sin_family = AF_INET;
    server_addr5.sin_addr.s_addr = inet_addr("10.255.0.12");
    server_addr5.sin_port = htons(SERVER_PORT5);

    /* 创建socket */
    client_socket_fd5 = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_socket_fd5 < 0)
    {
        perror("Create Socket5 Failed:");
        exit(1);
    }

}

#endif //NEWLIBS_SOCKETINTERFACE_H


