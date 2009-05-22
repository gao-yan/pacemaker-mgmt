%module pymgmt
%newobject mgmt_recvmsg;
%newobject mgmt_sendmsg;
%newobject mgmt_thread_sendmsg;

%{
#include "../../include/mgmt/mgmt_client.h"

char* mgmt_thread_sendmsg(const char* msg)
{
        char* ret_msg;
        Py_BEGIN_ALLOW_THREADS
        ret_msg = mgmt_sendmsg(msg);
        Py_END_ALLOW_THREADS      
        return ret_msg;
}
%}

int mgmt_connect(const char* server, const char* user, const char*  passwd, const char* port);
char* mgmt_sendmsg(const char* msg);
char* mgmt_recvmsg(void);
char* mgmt_thread_sendmsg(const char* msg);
int mgmt_inputfd(void);
int mgmt_disconnect(void);
