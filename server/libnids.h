//
// Created by jyc on 17-1-3.
//

#ifndef NEWLIBS_LIBNIDS_H
#define NEWLIBS_LIBNIDS_H

#endif //NEWLIBS_LIBNIDS_H

#include <glib.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

//mutex queue
static GAsyncQueue *cap_queue;
static GAsyncQueue *udp_queue;


