#include "haclient.h"

int main(void)
{
	unsigned long count;
	const struct hb_node_t * node = NULL;
	int i;

	(void) _ha_msg_h_Id;

	if (init_heartbeat() != HA_OK) {
		printf("init_heartbeat error\n");
	}
	if (get_node_count(&count) != HA_OK) {
		printf("get_node_count error\n");
	}
	for (i = 0; i < count; i++) {
		if (get_node_info(i, &node) != HA_OK) {
			printf("get_node_info error, i = %d\n", 
					i);
		}
                printf("b4 getting node info. node = %p\n", node);
		printf(" node name = %s, status = %s\n",
				node->name, node->status);
	}
	return 0;
}
