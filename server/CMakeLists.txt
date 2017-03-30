cmake_minimum_required(VERSION 3.5)
project(Newlibs)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
include_directories(/usr/local/include /usr/lib/glib-2.0/include  /usr/lib/x86_64-linux-gnu/glib-2.0/include /usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "/home/jyc/myproject/Newlibs/bin/")
add_executable(Newcaps Newcaps.cpp checksum.c config.h dns.h hash.h hash.c http_parser.c http_test.h ip_fragment.c ip_options.c nids.h tcp.h tcp.c util.c util.h libnids.c socketinterface.h libnids.h)
target_link_libraries(Newcaps pcap "/usr/local/lib/libgthread-2.0.so" "/usr/local/lib/libglib-2.0.so")