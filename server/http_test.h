/*
 *这个程序是http_paser的配置文件
 */
#include <stdio.h>
#include <string.h>
#include <map>
#include <algorithm>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


#ifndef TEST_HTTPPARSER_HTTP_TEST_H
#define TEST_HTTPPARSER_HTTP_TEST_H

#endif //TEST_HTTPPARSER_HTTP_TEST_H
using namespace std;


struct http_parser_settings ms_settings;
struct http_parser_settings ms_settings_response;


typedef enum{NOTHING,FIELD,VALUE} last_on_header_t;
last_on_header_t last_on_header;
map<std::string, std::string> headers;
map<std::string, std::string>::iterator I;
string header_field,header_value;

typedef enum{NOTHING1,FIELD1,VALUE1} last_on_header_t_response;
last_on_header_t_response last_on_header_response;
map<std::string, std::string> headers_response;
map<std::string, std::string>::iterator I2;
string header_field_response,header_value_response;


extern string http_result;
extern string http_response;
extern int method;

extern struct sockaddr_in server_addr;
extern int client_socket_fd;

extern struct sockaddr_in server_addr2;
extern int client_socket_fd2;

class HttpParserSettings
{
        public:
        HttpParserSettings();
        static int onMessageBegin(struct http_parser *);
        static int onUrl(struct http_parser *, const char *, size_t);
        static int onStatusComplete(struct http_parser *);
        static int onHeaderField(struct http_parser *, const char *, size_t);
        static int onHeaderValue(struct http_parser *, const char *, size_t);
        static int onHeadersComplete(struct http_parser *);
        static int onBody(struct http_parser *, const char *, size_t);
        static int onMessageComplete(struct http_parser *);

};



HttpParserSettings::HttpParserSettings()
{
    ms_settings.on_message_begin = &HttpParserSettings::onMessageBegin;
    ms_settings.on_url = &HttpParserSettings::onUrl;
    ms_settings.on_header_field = &HttpParserSettings::onHeaderField;
    ms_settings.on_header_value = &HttpParserSettings::onHeaderValue;
    ms_settings.on_headers_complete = &HttpParserSettings::onHeadersComplete;
    ms_settings.on_body = &HttpParserSettings::onBody;
    ms_settings.on_message_complete = &HttpParserSettings::onMessageComplete;


}



int HttpParserSettings::onMessageBegin(struct http_parser *parser)
{
    headers.clear();
    header_field = "";
    header_value = "";
    last_on_header = NOTHING;
    return 0;
}

int HttpParserSettings::onUrl(struct http_parser *parser, const char *at, size_t length)
{
//        printf("-----------------------------\n");
//        printf("%d\n",length);length
        string filed =string(at,length);
        headers["url"] = filed;
//        printf("-----------------------------\n");
        return 0;
}


int HttpParserSettings::onHeaderField(struct http_parser *parser, const char *at, size_t length)
{
    string field(at,length);
    transform(field.begin(), field.end(), field.begin(), ::tolower);

    switch(last_on_header)
    {
        case NOTHING:
                // Allocate new buffer and copy callback data into it
            header_field = field;
            break;
        case VALUE:
                // New header started.
                // Copy current name,value buffers to headers
                // list and allocate new buffer for new name
            headers[header_field] = header_value;
            header_field = field;
            break;
        case FIELD:
                // Previous name continues. Reallocate name
                // buffer and append callback data to it
            header_field.append(field);
            break;
    }
    last_on_header = FIELD;
    return 0;
}

int HttpParserSettings::onHeaderValue(struct http_parser *parser, const char *at, size_t length)
{
    const std::string value(at,length);
    switch(last_on_header)
    {
        case FIELD:
                //Value for current header started. Allocate
                //new buffer and copy callback data to it
            header_value = value;
            break;
        case VALUE:
                //Value continues. Reallocate value buffer
                //and append callback data to it
            header_value.append(value);
            break;
        case NOTHING:
                // this shouldn't happen
            printf("%s\n","Internal error in http-parser");
            break;
    }
    last_on_header = VALUE;

    return 0;
}

int HttpParserSettings::onHeadersComplete(struct http_parser *parser)
{
    time_t timep;
    time (&timep);

//        headers["url"] = "http://"+headers["host"]+headers["url"];
    if (last_on_header==VALUE)
    {
        headers[header_field] = header_value;
        header_field="";
    }
    http_result.append("\t");
    http_result.append(headers["host"]);
    http_result.append("\t");
//        http_result.append(headers["url"]);
//        http_result.append("\t")
    http_result.append(headers["referer"]);
    http_result.append("\t");
    http_result.append(headers["user-agent"]);

    if(method==1)
    {
        http_result.append("\t");
        http_result.append(headers["content-type"]);

    }

    http_result.append("\n");
//        printf("%s\n",http_result.c_str());
    if(sendto(client_socket_fd, http_result.c_str(), http_result.length(),0,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0)
    {
        perror("Send File Name Failed:");
        exit(1);
    }

    http_result.clear();
    headers.clear();
    header_field = "";
    header_value = "";
    last_on_header = NOTHING;
    return 1;
}

int HttpParserSettings::onBody(struct http_parser *parser, const char *at, size_t length)
{
//        string filed =string(at,length);
//        printf("body:%s\n", filed.c_str());
    return 0;

}

int HttpParserSettings::onMessageComplete(struct http_parser *parser)
{

    return 0;
}


class HttpParser_response
{
public:
    HttpParser_response();
    static int onMessageBegin_response(struct http_parser *);
    static int onUrl_response(struct http_parser *, const char *, size_t);
    static int onStatusComplete_response(struct http_parser *);
    static int onHeaderField_response(struct http_parser *, const char *, size_t);
    static int onHeaderValue_response(struct http_parser *, const char *, size_t);
    static int onHeadersComplete_response(struct http_parser *);
    static int onBody_response(struct http_parser *, const char *, size_t);
    static int onMessageComplete_response(struct http_parser *);

};

HttpParser_response::HttpParser_response()
{
    ms_settings_response.on_message_begin = &HttpParser_response::onMessageBegin_response;
    ms_settings_response.on_url = &HttpParser_response::onUrl_response;
    ms_settings_response.on_header_field = &HttpParser_response::onHeaderField_response;
    ms_settings_response.on_header_value = &HttpParser_response::onHeaderValue_response;
    ms_settings_response.on_headers_complete = &HttpParser_response::onHeadersComplete_response;
    ms_settings_response.on_body = &HttpParser_response::onBody_response;
    ms_settings_response.on_message_complete = &HttpParser_response::onMessageComplete_response;
}

int HttpParser_response::onMessageBegin_response(struct http_parser *parser)
{
    headers_response.clear();
    header_field_response = "";
    header_value_response = "";
    last_on_header_response = NOTHING1;
    return 0;
}

int HttpParser_response::onUrl_response(struct http_parser *parser, const char *at, size_t length)
{
//        printf("-----------------------------\n");
//        printf("%d\n",length);length
    return 0;
}


int HttpParser_response::onHeaderField_response(struct http_parser *parser, const char *at, size_t length)
{
    string field(at,length);
    transform(field.begin(), field.end(), field.begin(), ::tolower);

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
    last_on_header_response = FIELD1;
    return 0;
}

int HttpParser_response::onHeaderValue_response(struct http_parser *parser, const char *at, size_t length)
{
    const std::string value(at,length);
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
            printf("%s\n","Internal error in http-parser");
            break;
    }
    last_on_header_response = VALUE1;

    return 0;
}

int HttpParser_response::onHeadersComplete_response(struct http_parser *parser)
{
    time_t timep;
    time (&timep);

//        headers["url"] = "http://"+headers["host"]+headers["url"];
    if (last_on_header_response==VALUE1)
    {
        headers_response[header_field_response] = header_value_response;
        header_field_response="";
    }

    http_response.append(headers_response["content-type"]);
//        http_result.append(headers["url"]);
//        http_result.append("\t")
    http_response.append("\n");
//        printf("%s\n",http_response.c_str());
    if(sendto(client_socket_fd2, http_response.c_str(), http_response.length(),0,(struct sockaddr*)&server_addr2,sizeof(server_addr2)) < 0)
    {
        perror("Send File Name Failed:");
        exit(1);
    }

    http_response.clear();


    headers_response.clear();
    header_field_response = "";
    header_value_response = "";
    last_on_header_response = NOTHING1;
    return 1;
}

int HttpParser_response::onBody_response(struct http_parser *parser, const char *at, size_t length)
{
//        string filed =string(at,length);
//        printf("body:%s\n", filed.c_str());
    return 0;

}

int HttpParser_response::onMessageComplete_response(struct http_parser *parser)
{

    return 0;
}
