## 分布式抓包模块开发文档

>**文档作者：景彦超**  	
>**邮箱 13541333146@163.com**
>
>版本v2.0

[TOC]

### 抓包模块功能

抓包模块的功能是通过混杂模式收集互联网上的以太帧裸流量数据，并对裸流量帧数据进行ip重组，TCP重组，UDP分流等处理，并最终解析出HTTP，DNS等应用层协议头部的关键字段，将字段数据进行分发便于其他的模块使用。并对底层网络流量进行统计与分析。

### 程序架构说明

抓包模块分为master和server两个子模块.

master模块从网卡快速获取裸流量数据，并快速解析得到每个以太帧所包含的四元组信息（源ip地址，源端口地址，目的ip地址，目的端口地址）然后采用hash算法计算每个四元组对应的hash值，然后根据hash值将以太帧的数据封装成udp报文传给不同的socket接口，这里的socket接口可以是不同网卡上的socket地址。以此完成数据分发。master模块相当于数据生产者(其实是底层数据的分发者)。

server子模块的功能就是从master模块提供的socket端口中获取裸流量的数据，然后将数据进行头部解析，ip分片重组，tcp报文重组，udp报文处理，并最终提供出HTTP DNS等应用层协议的数据解析结果。

程序架构示意图如下所示：

![p3](.\picture\p3.png)



接下来对两个模块的实现细节进行详解。

### Master模块说明

#### 功能

> master模块从网卡快速获取裸流量数据，并根据裸流量帧的四元组信息将裸流量帧数据进行均等分发。交给server模块处理，降低单个server模块的数据处理量。

#### 开发环境搭建

> master模块使用到了libpcap和glib相关工具，其网站是https://github.com/the-tcpdump-group/libpcap.git和https://developer.gnome.org/glib/2.51/

工欲善其事必先利其器，所以搭建一个合适的开发环境是比较重要的，要开发抓包模块需要依赖，libpcap动态库，glib库）

所以首先需要自行安装这些库，安装步骤看各自github官网，说说检验的步骤，安装完成后需要查看一下目录检查是否安装成功：

> 检验libpcap：查看是否有/usr/local/lib/libpcap.a 和 /usr/local/lib/libpcap.so 这两个文件
>
> 检验glib：查看/usr/include/glib-2.0  /usr/lib/x86_64-linux-gnu/glib-2.0/include  /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include  /usr/lib/x86_64-linux-gnu/libgthread-2.0.so 这几个目录和文件

#### 模块架构与实现

模块由4个部分组成，其示意图如下所示：

![p2](.\picture\p2.png)

##### 1.pcap数据抓取代码

> 代码基于目前的成熟开源项目libpcap，https://github.com/the-tcpdump-group/libpcap.git

首先需要获取网卡设备描述符号

其代码如下所示

```c++
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
```

然后开启pcap抓包程序

```c++
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
```

libpcap将所获取的裸流量帧通过回调函数的形式传给上层函数调用,并且对link_offset（物理层类型）进行判断

```C++
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
```

然后进行获取四元组的工作，不过由于libpcap抓包对并发度和性能要求较高，采用单一线程的形式难以对libpcap所采集的数据进行及时处理，所以考虑使用多线程+异步队列的编程框架进行加速。为了方便管理多个线程于是决定采用线程池。以下是线程池模块。

##### 2.线程池加速模块

> 代码基于目前成熟的c语言环境库glib进行开发，https://developer.gnome.org/glib/2.51/

glib需要提前安装

首先需要初始化线程池，并注册回调函数

```C++
void start_pcap_thread()
{
  	//process_packet 是程序员自行编写的数据处理回调函数
    pool = g_thread_pool_new(process_packet,NULL,-1,FALSE,&gerror);
}
```

然后在pcap_func函数中，将需要异步处理的数据push进入线程池的异步队列中

```C++
g_thread_pool_push(pool, (gpointer *)info , NULL);
```

接着需要实现在线程池中注册的回调函数

```C++
static void process_packet(gpointer data,gpointer user_data)
{
    struct pcap_info* qitem;
    qitem = (struct pcap_info *) data;
    /* EOF item received: we should exit */
    num_pro++;
    u_char* copy_data = qitem->data;
    qitem->data+=18;
    ip_header* iphdr = (ip_header*)qitem->data;

    qitem->data+=sizeof(ip_header);

    if(iphdr->prot == 6)
    {
		//process TCP 
    }
    else if(iphdr->prot ==17)
    {
 		//process UDP
    }
  	
    free(copy_data);
    free(qitem);
}
```

这里gpointer是异步队列里面的数据，然后进行简单的头部解析，获取四元组。线程由线程池动态管理。

##### 3.hash四元组解析

对于裸流量数据，需要进行以太帧头部解析，ip头部解析，udp，tcp头部解析，目的是获取相应的四元组格式数据（源ip，源端口，目的ip，目的端口）

然后将利用四元组信息计算相应的hash数值，下面介绍hash算法

首先初始化hash函数

```c++
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
```

这两个函数的目的是随机生成一个六元数组perm，这个六元数组后面有用，getrnd函数作用是获取xor2和perm两个中间数据，随机方法是机器随机方法（利用机器的输入输出来随机，基本是完全随机）。

在初始化后就等待程序传入四元组，计算hash值

```c++
u_int mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
  	//异或运算，便于消除源和目的顺序影响
    u_int flag1 = src^dest;
    u_short flag2 = sport^dport;
    u_int res = 0;
    int i;
    u_char data[6];
    memcpy(data, &flag1, 4);
    memcpy(data+4,&flag2,2);
    for (i = 0; i < 6; i++)
      	//移位运算并利用大素数取余数
        res = ( (res << 8) + (data[perm[i]] ^ xor2[i])) % 0xff100f;
    return res;
}
```

在得到hash值以后根据分发的份数取余数进行分发，以下是分成多份的示例，num_hash表示分发的类数

```c++
res%num_hash
```

最后就是socket分发

##### 4.socket分发

通过udp协议进行分发，可以向多个端口分发，其数据结构以及书用函数定义如下所示：

```c++
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
```

到此，整个client模块的代码就介绍完毕了。运行client模块的方法是：

```
$sudo ./Master eno2 4
```

其中pcapclient是可执行文件。



### Server模块介绍

#### 功能

> server模块从网卡端口快速获取master节点分发的数据，并对数据进行DPI解析，实现IP重组，TCP重组等，最终解析出HTTP协议和DNS协议并完成输出

server模块是比较复杂的，很多libnids的原生模块不展开介绍，本节主要介绍下如何使用这些模块以及二次开发的模块的相关部分。

#### 开发环境搭建

> server模块的基本框架是基于开源网络库libnids进行二次开发，其网站是 https://github.com/MITRECND/libnids.git

工欲善其事必先利其器，所以搭建一个合适的开发环境是比较重要的，要开发抓包模块需要依赖，libpcap动态库，libnsl动态库，glib库，libnet静态库）

所以首先需要自行安装这些库，安装步骤看各自github官网，说说检验的步骤，安装完成后需要查看一下目录检查是否安装成功：

> 检验libpcap：查看是否有/usr/local/lib/libpcap.a 和 /usr/local/lib/libpcap.so 这两个文件
>
> 检验glib：查看/usr/include/glib-2.0  /usr/lib/x86_64-linux-gnu/glib-2.0/include  /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include  /usr/lib/x86_64-linux-gnu/libgthread-2.0.so 这几个目录和文件

libnids不需要先静态编译生成静态库文件再引用，这样效率太低，于是直接将程序集成到libnids的代码中。集成后的代码就具有像模块架构图中所示的全部结构了。

接下来就逐个子模块来分析讲解。

#### 模块架构与实现

首先看一下整个的模块架构：

![p4](.\picture\p4.png)

##### 1.socket模块与接口

socket模块的作用是代替原来的libpcap模块获取数据包的原始数据，并且交给上层处理。首先看到libnids的执行入口libnids.c文件中的nids_run函数

```c++
//libnids.c
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
        memcpy(data,recvBuffer,len);
      	//获取时间信息
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
```

如果对照这里的关键接口还是nids_pcap_handler，也就是说，虽然将libnids的libpcap接收接口换成了socket接口，但是将数据提交的接口没有变化，甚至连输入参数都改变.接口将从udp端口获取的报文的数据直接构造成libpcap的输入格式。这里需要注意的是libpcap的结构体中有一个 hrd->ts 的时间变量，这个变量需要被赋值。

这里的init_socket()很直观，就是建立socket监听服务器。

##### 2.网络数据报文处理流程

然后从Callback开始一直到ip assemble 都是完整的libnids的代码，没有进行修改，需要注意的是，libnids的多线程机制是在解析完成以太帧头部后，将从ip层开始的数据放入了一个名为cap_queue的异步队列中，然后开启一个线程从异步队列里面获取数据。

开启线程的函数是：

```c++
//libnids.c
int static START_CAP_QUEUE_PROCESS_THREAD()
{
    printf("Thread start\n");
    if(nids_params.multiproc)
    { /* threading... */
        if(!(g_thread_create((GThreadFunc)cap_queue_process_thread, (gpointer)(1), FALSE, &gerror))) {
            strcpy(nids_errbuf, "thread: ");
            strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8);
            return 0;
        }
    }
}
```



解析到udp的时候，在libnids的基础上加上了一个线程，将udp报文的数据和四元组一起放入一个名为udp_queue的异步队列中，然后使用一个线程去获取异步获取队列里的数据，并将数据传给上层的回调函数udp_protocol_callback。实现并行化。

而TCP方面，TCP重组的模块并没有修改，直接使用libnids中提供的TCP重组代码，代码在tcp.c文件中。TCP重组完成后就会把代码传给上层回调tcp2_protocol_callback函数然后实现tcp的相关处理。

下面就分析一下TCP流重组的过程和原理：

##### 3.TCP流重组

在tcp.h中有个数据结构：

```C++
struct skbuff
{
  struct skbuff *next;
  struct skbuff *prev;

  void *data;
  u_int len;
  u_int truesize;
  u_int urg_ptr;
  
  char fin;
  char urg;
  u_int seq;
  u_int ack;
};
```

这时内核中的数据结构的简化版，具体介绍可以看这个博客：http://blog.csdn.net/shanshanpt/article/details/21024465

在nid.h中有：

```c++
struct tuple4  
{  
     u_short source;  
     u_short dest;  
     u_int saddr;  
     u_int daddr;  
};  
```

这是连接的四元组

```c++
    struct half_stream  
    {  
      char state;  
      char collect;  
      char collect_urg;  
       
      char *data; //这里存放着已经按顺序集齐排列好的数据  
      int offset;  
      int count; //这里存放data中数据的字节数  
      int count_new; //这里存放data中还没回调过的数据的字节数  
      int bufsize;  
      int rmem_alloc;  
       
      int urg_count;  
      u_int acked;  
      u_int seq;  
      u_int ack_seq;  
      u_int first_data_seq;  
      u_char urgdata;  
      u_char count_new_urg;  
      u_char urg_seen;  
      u_int urg_ptr;  
      u_short window;  
      u_char ts_on; //tcp时间戳选项是否打开  
      u_char wscale_on; //窗口扩展选项是否打开  
      u_int curr_ts;  
      u_int wscale;  
       
      //下面是ip包缓冲区  
      struct skbuff *list;  
      struct skbuff *listtail;  
    }  
```

这是表示半连接的

```c++
    struct tcp_stream  
    {  
      struct tuple4 addr;  
      char nids_state;  
      struct lurker_node *listeners;  
      struct half_stream client;  
      struct half_stream server;  
      struct tcp_stream *next_node;  
      struct tcp_stream *prev_node;  
      int hash_index;  
      struct tcp_stream *next_time;  
      struct tcp_stream *prev_time;  
      int read;  
      struct tcp_stream *next_free;  
      void *user;  max_stream = 3 * tcp_stream_table_size / 4;
    };  
```

这是用来表示一个完整的会话的。

处理过程如下：

可以参见博客：http://blog.csdn.net/msda/article/details/8494561

这里说下tcp流的存储形式以及定时器

tcp流以tcp_stream的结构存在名为tcp_stream_table的数组中（其实是一个hash表），这个tcp_stream_table是一个拉链式hash数组。

每个拉链的元素来源于free_streams这个提前申请好的链表中（这个链表的总长度为max_stream = 3 * tcp_stream_table_size / 4;）

其余就与hash算法完全相同了。

而定时器分为两种，一种是系统里的保活定时器，10秒。并且每个流的定时器存放在一个双向链表上面，每次收到数据后更新时间。

然后就是神奇的地方了，判断时间是否到时不是由信号来提醒的，而是由这个函数来处理

```c++
tcp_check_timeouts(struct timeval *now)
```

那么这个函数是怎么被调用的呢，这个函数是在每收到一个数据包的时候，对就是server的最底层，每从master收到一个数据后就判断tcp的计时器。

第二个定时器是系统配置用于在如果第一个计时器无法被使用时，以系统配置来删除老旧的流。

##### 4.使用tcp数据得到http协议

###### 4.1.接收数据格式

之前介绍的部分都是对libnids的原代码进行的修改。不过libnids的功能仅仅是获取TCP和UDP的数据，完成对碎片报文重组。并没有提供上层(应用层)数据的解析。不过libnids为用户提供了扩展接口，就是让用户自己去注册tcp和udp数据的回调函数，获取底层解析出来的udp和tcp的数据值然后执行编写程序进行处理。

TCP回调函数使用方法如下所示：

```c++
nids_register_tcp((void *) tcp2_protocol_callback);
```

其中tcp2_protocol_callback是用户自定义的回调函数，不过输入参数是确定的。如下所示

```c++
tcp2_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
```

解释下参数，对于tcp2_protocol_callback， struct tcp_stream是libnids自定义的流数据结构，里面包含了一条TCP流的全部信息，包括client和server，如下所示：

> 在nids.h文件中

```c++
//nids.h
struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
  long ts;
};
```

###### 4.2.回调函数处理流程

TCP回调函数会在TCP流的各个阶段被回调，比如TCP流刚刚三次握手完成后，又比如TCP传输数据时，TCP流正常关闭时，TCP被RST关闭。其状态由tcp_connection->nids_state变量记录。所以TCP回调函数处理框架如下所示：

```c++
void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    char address_string[1024];
    struct tuple4 ip_and_port = tcp_connection->addr;
    switch (tcp_connection->nids_state) /*Listen*/
    {

        case NIDS_JUST_EST:
            /*建立连接*/
            return;
        case NIDS_CLOSE:
            /*TCP连接正常关闭 */
            return;
        case NIDS_RESET:
            /* TCP被RST关闭 */
            return ;
        case NIDS_DATA:
            /* 有数据到达 */
            return;
        case NIDS_TIMED_OUT:
            /* 连接超时 */
            return;
        default:
            break;
    }
    return ;
}
```

在每个case下填写相应的处理过程。在server模块中这里的建立连接case下的代码如下所示：

```c++
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
```

这里目的很明显是选择那些目的端口或者源端口为80的流(HTTP协议)，然后collect++的作用是同意接收数据，如果不设定的话，就默认不接收数据。这里libnids将一条流分成了客户端和服务器，所以l两端均需要指定。

然后就是数据接收了，这里需要说明下这个状态：

```c++
case NIDS_DATA:/* 有数据到达 */
```

在这个状态下,底层会传入一个TCP流中的一个报文，实际就是一个ip分片，所以在这一步无法获取完整的TCP报文。并不能进行HTTP的解析。所以选择流正常关闭的case

```C++
case NIDS_CLOSE:/*TCP连接正常关闭 */
```

这里libnids会把用户在client和server两端的全部数据都保存下来，在这一步获得HTTP流量就是完整的了，可以开始对HTTP进行解析。

``` c++
case NIDS_TIMED_OUT:/*TCP连接正常关闭 */
```

这里libnids会把在tcp流重组过程中超时的流输出

###### 4.3.HTTP 解析步骤

在TCP正常关闭后，从回调函数接收到完整的HTTP数据。

1.判断是http request还是http response进程，如果是http request报文,传入request_queue的异步队列，如果是http response传入response的异步队列。

2.两个异步队列中的数据分别由不同的线程进行处理。

3.线程的步骤是:逐个将HTTP输出需要的数据传入（比如时间，大小，四元组，请求类型）然后申请一个新的http_parser对象，并将HTTP的原始数据传入http_parser完成HTTP头部解析并输出。关于http_parser下个章节将会介绍。

###### 3.4.HTTP parser开源项目

解析时采用了成熟的HTTP解析开源代码http_parser

>http_parser网址如下所示：https://github.com/dexgeh/http_parser.git

http_parser使用很简单，就是注册一个包含各种回调函数的结构体，然后传入需要解析的HTTP数据，之后就可以进行解析了。各种回调函数会在HTTP报文的不同的解析阶段被回调，用户就可以在不同回调函数中书写处理过程就行了。

这个需要设置的数据结构是：

```c++
struct http_parser_settings 
```

这里将这个数据结构包装到一个类中，然后通过这个类将所有的回调函数都统一起来。

然后在每个回调函数里面单独写方法,主要有如下的回调方法

>on_message_begin     当http开始解析时,传入用户自定义参数
>
>on_url  当解析到请求的url时，传入url字段数据和长度
>
>on_header_field 当解析到头部field域时，比如Accept：XXXXX的Accept时，传入Accept
>
>on_header_value 当解析到头部value域时，比如Accept：XXXXX的XXXXX时，传入XXXXX
>
>on_headers_complete 当头部解析完成时,传入用户自定义参数
>
>on_body 当解析到body部分时传入body数据和长度
>
>on_message_complete 当http解析完成时，传入用户自定义参数

在每个方法内写入相应的处理过程，不写就默认不处理。

这里需要说明的是**on_header_field和on_header_value**这两个回调函数的处理过程。

首先分析下，我们的需求，就是得到一个map，可以方便地通过field查询得到value。由于解析的时候field与value不一定交替出现，并且为了处理异常情况，就设计了一种状态机机制。设置三种状态如下所示：

>Nothing
>
>Field
>
>Value

Nothing 代表空状态,Field代表上一个状态是刚接收完field，Value代表上一个状态是刚接收完value.

所以设置状态机，根据上一个状态和当前状态共同决定相应的操作步骤。

对应的代码如下：

首先是field

```c++
switch(last_on_header_response)
{
    case NOTHING1:
        // Allocate new buffer and copy callback data into it
        header_field_response = field;
        break;
    case VALUE1:
        // New header started.
        // Copy current name,value buffers to headers
        // list and allocate new buffer for new name
        headers_response[header_field_response] = header_value_response;
        header_field_response = field;
        break;
    case FIELD1:
        // Previous name continues. Reallocate name
        // buffer and append callback data to it
        header_field_response.append(field);
        break;
}
```

然后是value

```c++
switch(last_on_header_response)
{
    case FIELD1:
        //Value for current header started. Allocate
        //new buffer and copy callback data to it
        header_value_response = value;
        break;
    case VALUE1:
        //Value continues. Reallocate value buffer
        //and append callback data to it
        header_value_response.append(value);
        break;
    case NOTHING1:
        // this shouldn't happen
        printf(stderr,"%s\n","Internal error in http-parser");
        break;
}
```

根据不同的情况进行状态轮转，最后得到一个map，并以field:value的键值对存储。

当http的头部解析完成后http报文就算是解析完成了，所以在on_headers_complete的回调函数中将HTTP需要的字段加入输出字段中，然后输出.

##### 5.使用udp数据得到udp协议

###### 5.1.接收数据格式

UDP回调函数使用方法如下所示：

```
nids_register_udp((void *) udp_protocol_callback);
```

其中udp_protocol_callback是用户自定义的回调函数，不过输入参数是确定的。如下所示

```c++
udp_protocol_callback(struct tuple4 *addr,  char  * buf,  int  len)
```

对于udp_protocol_callback，struct tuple4 是libnids自定义的四元组数据结构，如下所示：

> 在nids.h文件中

```c++
struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};
```

buf是数据，len是数据长度。

###### 5.2.DNS请求报文解析

首先确定是请求报文

```c++
if(addr->dest == 53)
{
    dns_parser_request(addr,buf,len);
}
```

然后就是dns_parser_request函数了,在dns.h中可以看到原代码

解析步骤如下所示：

1.获取DNS报文头部，判断flag最高位是否为0

2.解析DNS请求的域名字段

3.解析DNS请求类型和请求格式

4.将四元组，长度等字段加入，然后输出

###### 5.3.DNS请求报文解析

首先确定是返回报文

```c++
else if(addr->source == 53)
{
    dns_parser_response(addr,buf,len);
}
```

然后就是dns_parser_response函数了,在dns.h中可以看到原代码

解析步骤如下所示：

1.获取DNS报文头部，判断flag最高位是否为0

2.解析DNS请求的域名字段

3.解析DNS返回类型和返回格式

4.解析DNS的url

5.将四元组，长度等字段加入，然后输出









































