#ifndef __libhasubagent_h__
#define __libhasubagent_h__

#include <clplumbing/cl_log.h>
#include "hb_api.h"

struct hb_node_t {
	char * name;
	char * status;
	unsigned long ifcount;
};

struct hb_if_t {
	const char * name;
	const char * status;
};

int init_heartbeat(void);
int get_node_count(unsigned long * count);
int get_node_info(unsigned long index, const struct hb_node_t ** node);

#endif // __libhasubagent_h__
