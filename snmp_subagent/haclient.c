#include "haclient.h"

#include <sys/types.h>
#include <unistd.h>
#include <glib.h>

unsigned long hbInitialized;

ll_cluster_t * hb = NULL;
GArray * gNodeTable;
GArray * gIFTable;

void NodeStatus(const char * node, const char * status, void * private);
void LinkStatus(const char * node, const char * lnk, const char * status 
,       void * private);

int init_node_table(void);
int init_if_table(const char * node);

void
NodeStatus(const char * node, const char * status, void * private)
{
        cl_log(LOG_NOTICE, "Status update: Node %s now has status %s\n"
        ,       node, status);
}

void
LinkStatus(const char * node, const char * lnk, const char * status
,       void * private)
{
        cl_log(LOG_NOTICE, "Link Status update: Link %s/%s now has status %s\n"
        ,       node, lnk, status);
}

int
init_heartbeat(void)
{
	(void)_ha_msg_h_Id;
	hb = NULL;

	cl_log_set_entity("hasubagent");
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	hb = ll_cluster_new("heartbeat");

	cl_log(LOG_DEBUG, "PID=%ld\n", (long)getpid());
	cl_log(LOG_DEBUG, "Signing in with heartbeat\n");

	if (hb->llc_ops->signon(hb, NULL)!= HA_OK) {
		cl_log(LOG_ERR, "Cannot sign on with heartbeat\n");
		cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}

	if (hb->llc_ops->set_nstatus_callback(hb, NodeStatus, NULL) !=HA_OK){
	        cl_log(LOG_ERR, "Cannot set node status callback\n");
	        cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}

	if (hb->llc_ops->set_ifstatus_callback(hb, LinkStatus, NULL)!=HA_OK){
	        cl_log(LOG_ERR, "Cannot set if status callback\n");
	        cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}
	return init_node_table();
}

int
init_node_table(void)
{
	const char *nname;
	const char *nstatus;
	struct hb_node_t node;

	gNodeTable = g_array_new(TRUE, TRUE, sizeof (struct hb_node_t));
	gIFTable = g_array_new(TRUE, TRUE, sizeof (struct hb_if_t));

	if (hb->llc_ops->init_nodewalk(hb) != HA_OK) {
		cl_log(LOG_ERR, "Cannot start node walk\n");
		cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}
	while((nname = hb->llc_ops->nextnode(hb))!= NULL) {
		nstatus = hb->llc_ops->node_status(hb, nname);

		cl_log(LOG_DEBUG, "Cluster node: %s: status: %s\n", nname 
		,	nstatus);

		node.name =  g_strdup(nname);
		node.status =  g_strdup(nstatus);
		g_array_append_val(gNodeTable, node); 

	}
	if (hb->llc_ops->end_nodewalk(hb) != HA_OK) {
		cl_log(LOG_ERR, "Cannot end node walk\n");
		cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}
	return HA_OK;
}

int
init_if_table(const char * node)
{
	const char * ifname;
	const char * ifstatus;
	struct hb_if_t interface;

	if (hb->llc_ops->init_ifwalk(hb, node) != HA_OK) {
		cl_log(LOG_ERR, "Cannot start if walk\n");
		cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}

	while((ifname = hb->llc_ops->nextif(hb))!=NULL) {
		ifstatus = hb->llc_ops->if_status(hb, node, ifname);

		cl_log(LOG_DEBUG, "node interface: %s: status: %s\n", ifname 
		,	ifstatus);

		interface.name = g_strdup(ifname);
		interface.status = g_strdup(ifstatus);
		g_array_append_val(gIFTable, interface);
	}

	if (hb->llc_ops->end_ifwalk(hb) != HA_OK) {
		cl_log(LOG_ERR, "Cannot end if walk\n");
		cl_log(LOG_ERR, "REASON: %s\n", hb->llc_ops->errmsg(hb));
		return HA_FAIL;
	}
	return HA_OK;
}

int
get_node_count(unsigned long * count)
{
	*count = gNodeTable->len;
	return HA_OK;
}

int
get_node_info(unsigned long index, const struct hb_node_t ** node)
{
	*node = &g_array_index(gNodeTable, struct hb_node_t, index);
	return HA_OK;
}
