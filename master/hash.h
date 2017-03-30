//
// Created by jyc on 17-3-16.
//

#ifndef MASTER_HASH_H
#define MASTER_HASH_H

#endif //MASTER_HASH_H
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
void init_hash();
u_int mkhash (u_int , u_short , u_int , u_short);
static u_char xor2[6];
static u_char perm[6];

// 生成随机数序列
static void getrnd ()
{
    struct timeval s;
    u_int *ptr;
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd > 0)
    {
        read (fd, xor2, 6);
        read (fd, perm, 6);
        close (fd);
        return;
    }
    gettimeofday (&s, 0);
    srand (s.tv_usec);
    ptr = (u_int *) xor2;
    *ptr = rand ();
    *(ptr + 1) = rand ();
    *(ptr + 2) = rand ();
    ptr = (u_int *) perm;
    *ptr = rand ();
    *(ptr + 1) = rand ();
    *(ptr + 2) = rand ();
}


//这里是生成一个乱序的数据下标
void init_hash ()
{
    int i, n, j;
    int p[6];
    getrnd ();
    for (i = 0; i < 6; i++)
        p[i] = i;
    for (i = 0; i < 6; i++)
    {
        n = perm[i] % (6 - i);
        perm[i] = p[n];
        for (j = 0; j < 5 - n; j++)
            p[n + j] = p[n + j + 1];
    }
}


//生成hash值
u_int mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
    u_int flag1 = src^dest;
    u_short flag2 = sport^dport;
    u_int res = 0;
    int i;
    u_char data[6];
    memmove(data, &flag1, 4);
    memmove(data+4,&flag2,2);
    for (i = 0; i < 6; i++)
        res = ( (res << 8) + (data[perm[i]] ^ xor2[i])) % 0xff100f;
    return res;
}