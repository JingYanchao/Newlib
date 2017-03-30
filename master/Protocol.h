//
// Created by jyc on 17-3-16.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#endif //MASTER_PROTOCOL_H

//应用层协议端口
const int DNS_PROT = 53;
const int SMTP_PROT = 25;
const int POP3_PORT = 110;
const int HTTP_PORT = 80;
const int HTTPS_PORT = 443;
const int TELNET_PORT = 23;
const int FTP_PORT = 20;

int num_dns = 0;
int num_smtp = 0;
int num_pop3 = 0;
int num_http = 0;
int num_https = 0;
int num_telnet = 0;
int num_ftp = 0;
int num_total = 0;

//mac 帧头部
struct mac_header
{
    char m_cDstMacAddress[6];  //目的mac地址
    char m_cSrcMacAddress[6];  //源mac地址
    short m_cType;  //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
};

struct ip_header
{
    unsigned char	vhl;		// version << 4 | header length >> 2
    unsigned char	tos;		// type of service
    unsigned short	len;		// total length
    unsigned short	id;			// identification
    unsigned short	off;		// fragment offset field
    unsigned char	ttl;		// time to live
    unsigned char	prot;		// protocol
    unsigned short	sum;		// checksum
    struct in_addr src;
    struct in_addr dst;	// source and dest address
};

struct tcp_header
{
    unsigned short	sport;	// source port
    unsigned short	dport;	// destination port
    unsigned int	seq;	// sequence number
    unsigned int	ack;	// acknowledgement number
    unsigned char	offx2;	// data offset, rsvd
    unsigned char	flags;  // 前4位：TCP头长度；中6位：保留；后6位：标志位
    unsigned short	win;	// window
    unsigned short	sum;	// checksum
    unsigned short	urp;	// urgent pointer
};

struct udp_header
{
    unsigned short	sport;		// source port
    unsigned short	dport;		// destination port
    unsigned short	length;		// udp length
    unsigned short	checksum;	// udp checksum
};

//四元组
struct tuple4
{
    u_short source;
    u_short dest;
    u_int saddr;
    u_int daddr;
};


