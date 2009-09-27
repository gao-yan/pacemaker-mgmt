/*
 *  Common library for Linux-HA management tool
 *
 * Author: Huang Zhen <zhenhltc@cn.ibm.com>
 * Copyright (C) 2005 International Business Machines
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __MGMT_COMMON_H
#define __MGMT_COMMON_H 1


/*************************PROTOCOL*******************************************/

/*
description
   increased, if daemon-client communication changes in an incompatible way
*/	
#define MGMT_PROTOCOL_VERSION "2.1"


/*************************MESSAGES*******************************************/

#define MSG_OK  		"o"
#define MSG_FAIL		"f"

#define CHR_OK  		'o'
#define CHR_FAIL		'f'

/*
description:
	login to daemon.
	the username/password must be one of the authorized account on the 
	server running the daemon
format:
	MSG_LOGIN username password protocolversion
return:
	MSG_OK 
or
	MSG_FAIL
*/
#define MSG_LOGIN		"login"

/*
description:
	logout from daemon
format:
	MSG_LOGOUT
return:
	MSG_OK
or
	MSG_FAIL
*/
#define MSG_LOGOUT		"logout"

/*
description:
	do nothing except return the string ANYSTRING.
	using for test the sanity of daemon.
format:
	MSG_ECHO anystring
return:
	MSG_OK anystring
or
	MSG_FAIL
*/
#define MSG_ECHO		"echo"

/*
description:
	register event EVENTTYPE.
	when the event invoked, the client would be notified.
format:
	MSG_REGEVT EVENTTYPE
return:
	MSG_OK
or
	MSG_FAIL
*/
#define MSG_REGEVT		"regevt"

/*
description:
	get the active CIB name
format:
	MSG_ACTIVE_CIB
return:
	MSG_OK <""|shadow_name>
*/
#define MSG_ACTIVE_CIB		"active_cib"

/*
description:
	shutdown working CIB.
format:
	MSG_SHUTDOWN_CIB 
return:
	MSG_OK
or
	MSG_FAIL REASON
*/
#define MSG_SHUTDOWN_CIB	"shutdown_cib"

/*
description:
	initiate working CIB.
format:
	MSG_INIT_CIB <""|shadow_name>
return:
	MSG_OK
or
	MSG_FAIL REASON
*/
#define MSG_INIT_CIB		"init_cib"

/*
description:
	change working CIB.
format:
	MSG_SWITCH_CIB <""|shadow_name>
return:
	MSG_OK
or
	MSG_FAIL REASON
*/
#define MSG_SWITCH_CIB		"switch_cib"

/*
description:
	get shadow CIB list
format:
	MSG_GET_SHADOWS
return:
	MSG_OK SHADOWNAME1 SHADOWNAME2 ... SHADOWNAMEn
or
	MSG_FAIL REASON
*/
#define MSG_GET_SHADOWS		"get_shadows"

/*
description:
	execute specified crm_shadow command
format:
	MSG_CRM_SHADOW command <""|shadow_name> is_force
return:
	MSG_OK
or
	MSG_FAIL REASON
*/
#define MSG_CRM_SHADOW		"crm_shadow"

/*
description:
	return the cluster type
format:
	MSG_CLUSTER_TYPE
return:
	MSG_OK cluster_type
or
	MSG_FAIL

*/
#define MSG_CLUSTER_TYPE	"cluster_type"

/*
description:
	return CIB version
format:
	MSG_CIB_VERSION
return:
	MSG_OK version
or
	MSG_FAIL
*/
#define MSG_CIB_VERSION		"cib_version"

/*
description:
	return the dtd of crm
format:
	MSG_CRM_SCHEMA VALIDATE_TYPE FILE
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL
*/
#define MSG_CRM_SCHEMA	"crm_schema"

/*
description:
	return the dtd of crm
format:
	MSG_CRM_DTD
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL
*/
#define MSG_CRM_DTD	"crm_dtd"

/*
description:
	return the metadata of crm
format:
	MSG_CRM_METADATA CRM_CMD
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL
*/
#define MSG_CRM_METADATA	"crm_metadata"

/*
description:
	get or set specified attribute
format:
	MSG_CRM_ATTRIBUTE type <get|set|del> attribute [value]
return:
	MSG_OK [value]
or
	MSG_FAIL reason
*/
#define MSG_CRM_ATTRIBUTE	"crm_attribute"

/*
description:
	return heartbeat configuration
format:
	MSG_HB_CONFIG
return:
	MSG_OK name1 value1 name2 value2 ... namen valuen
	MSG_FAIL
*/
#define MSG_HB_CONFIG		"hb_config"
#define F_MGMT_APIAUTH			1
#define F_MGMT_AUTO_FAILBACK		2
#define F_MGMT_BAUD			3
#define F_MGMT_DEBUG			4
#define F_MGMT_DEBUGFILE		5
#define F_MGMT_DEADPING			6
#define F_MGMT_DEADTIME			7
#define F_MGMT_HBVERSION		8
#define F_MGMT_HOPFUDGE			9
#define F_MGMT_INITDEAD			10
#define F_MGMT_KEEPALIVE		11
#define F_MGMT_LOGFACILITY		12
#define F_MGMT_LOGFILE			13
#define F_MGMT_MSGFMT			14
#define F_MGMT_NICE_FAILBACK		15
#define F_MGMT_NODE			16
#define F_MGMT_NORMALPOLL		17
#define F_MGMT_STONITH			18
#define F_MGMT_UDPPORT			19
#define F_MGMT_WARNTIME			20
#define F_MGMT_WATCHDOG			21
#define F_MGMT_CLUSTER			22

/*
description:
	return the name of all nodes configured in cluster
format:
	MSG_ALLNODES
return:
	MSG_OK node1 node2 ... noden
or
	MSG_FAIL
*/
#define MSG_ALLNODES		"all_nodes"

/*
description:
	return node's type
format:
	MSG_NODE_TYPE NODENAME
return:
	MSG_OK node_type("normal|ping|unknown")
or
	MSG_FAIL
*/
#define MSG_NODE_TYPE		"node_type"

/*
description:
	return active nodes configured in cluster
format:
	MSG_ACTIVENODES
return:
	MSG_OK node1 node2 ... noden
or
	MSG_FAIL
*/
#define MSG_ACTIVENODES 	"active_nodes"


/*
description:
	return nodes configured in crm
format:
	MSG_CRMNODES
return:
	MSG_OK node1 node2 ... noden
or
	MSG_FAIL
*/
#define MSG_CRMNODES 	"crm_nodes"

/*
description:
	return DC in cluster
format:
	MSG_DC
return:
	MSG_OK dc_node
or
	MSG_FAIL
*/
#define MSG_DC			"dc"

/*
description:
	return node's configured
format:
	MSG_NODE_CONFIG NODENAME
return:
	MSG_OK uname online(True|False) standby(True|False) unclean(True|False)
 	  shutdown(True|False) expected_up(True|False) is_dc(True|False)
	  node_ping("ping|member")
or
	MSG_FAIL
*/
#define MSG_NODE_CONFIG		"node_config"
#define F_MGMT_UNAME				1
#define F_MGMT_ONLINE				2
#define F_MGMT_STANDBY				3
#define F_MGMT_UNCLEAN				4
#define F_MGMT_SHUTDOWN			5
#define F_MGMT_EXPECTED_UP			6
#define F_MGMT_IS_DC				7
#define F_MGMT_NODE_PING			8
#define F_MGMT_NODE_PENDING			9
#define F_MGMT_NODE_STRANDBY_ONFAIL		10

/*
description:
	migrate a resource
format:
	MSG_MIGRATE rsc_id to_node force duration
return:
	MSG_OK 
or
	MSG_FAIL reason
*/
#define MSG_MIGRATE		"migrate"

/*
description:
	set standby on a node
format:
	MSG_STANDBY node on|off
return:
	MSG_OK 
or
	MSG_FAIL reason
*/
#define MSG_STANDBY		"standby"

/* new CRUD protocol */
/*
description:
    accomplish the cib commands
format:
    MSG_CIB_XXXXXX LINE
return:
    MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL
*/
#define MSG_CIB_CREATE		"cib_create"
#define MSG_CIB_QUERY		"cib_query"
#define MSG_CIB_UPDATE		"cib_update"
#define MSG_CIB_REPLACE		"cib_replace"
#define MSG_CIB_DELETE		"cib_delete"


/*
description:
	return names of all running resources on a given node
format:
	MSG_RUNNING_RSC node
return:
	MSG_OK resource1 resource2 ...  resourcen
or
	MSG_FAIL
*/
#define MSG_RUNNING_RSC		"running_rsc"

/*
description:
	return all resources in the cluster
format:
	MSG_ALL_RSC
return:
	MSG_OK resource1 resource2 ...  resourcen
or
	MSG_FAIL
*/
#define MSG_ALL_RSC		"all_rsc"

/*
description:
	return the type of a given resource
format:
	MSG_RSC_TYPE resource
return:
	MSG_OK type(unknown|native|group|clone|master)
or
	MSG_FAIL
*/
#define MSG_RSC_TYPE		"rsc_type"

/*
description:
	return the sub-resources of a given resource
format:
	MSG_SUB_RSC resource
return:
	MSG_OK sub-resource1 sub-resource2 ... sub-resourcen
or
	MSG_FAIL
*/
#define MSG_SUB_RSC		"sub_rsc"

/*
description:
	return the node on which the given resource is running on
format:
	MSG_RSC_RUNNING_ON resource
return:
	MSG_OK node
or
	MSG_FAIL
*/
#define MSG_RSC_RUNNING_ON	"rsc_running_on"

/*
description:
	return the status of a given resource
format:
	MSG_RSC_STATUS resource
return:
	MSG_OK status(unknown|unmanaged|failed|multi-running|running|group
			|clone|master)
or
	MSG_FAIL
*/
#define MSG_RSC_STATUS		"rsc_status"

/*
description:
	return the translated string of a operation status
format:
	MSG_OP_STATUS2STR STATUS
return:
	MSG_OK STRING
*/
#define MSG_OP_STATUS2STR       "op_status2str"

/*
description:
	clean up a unmanaged resource
format:
	MSG_CLEANUP_RSC node resource
return:
	MSG_OK
or
	MSG_FAIL
*/
#define MSG_CLEANUP_RSC		"cleanup_rsc"

/*
description:
	execute specified crm_resource command
format:
	MSG_CRM_RSC_CMD <rsc_id|""> command <host_uname|"">
return:
	MSG_OK
or
	MSG_FAIL [reason]
*/
#define MSG_CRM_RSC_CMD		"crm_rsc_cmd"

/*
description:
	set the named attribute for a given resource
format:
	MSG_SET_RSC_ATTR rsc_id <instance|meta> name value
return:
	MSG_OK
or
	MSG_FAIL
*/
#define MSG_SET_RSC_ATTR	"set_rsc_attr"

/*
description:
	get the named attribute for a given resource
format:
	MSG_GET_RSC_ATTR rsc_id <instance|meta> name
return:
	MSG_OK value
or
	MSG_FAIL
*/
#define MSG_GET_RSC_ATTR	"get_rsc_attr"

/*
description:
	delete the named attribute for a given resource
format:
	MSG_DEL_RSC_ATTR rsc_id <instance|meta> name
return:
	MSG_OK
or
	MSG_FAIL
*/
#define MSG_DEL_RSC_ATTR	"del_rsc_attr"

/*
description:
	return all resource classes of resource agents
format:
	MSG_RSC_CLASSES
return:
	MSG_OK class1 class2 ... classn
or
	MSG_FAIL
*/
#define MSG_RSC_CLASSES		"rsc_classes"

/*
description:
	return all resource type of a given class
format:
	MSG_RSC_TYPE class
return:
	MSG_OK type1 type2 ... typen
or
	MSG_FAIL
*/
#define MSG_RSC_TYPES		"rsc_types"

/*
description:
	return all provider of a given class and type
format:
	MSG_RSC_TYPE class type
return:
	MSG_OK provider1 provider2 ... providern
or
	MSG_FAIL
*/
#define MSG_RSC_PROVIDERS	"rsc_providers"

/*
description:
	return the metadata of a given resource type
format:
	MSG_RSC_METADATA RSC class type provider
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL
*/
#define MSG_RSC_METADATA	"rsc_metadata"

/*
description:
	return the translated string of a lrm_rsc_op return code
format:
	MSG_LRM_OP_RC2STR RC
return:
	MSG_OK STRING
*/
#define MSG_LRM_OP_RC2STR	"lrm_op_rc2str"

/*
description:
	generate cluster report and return the list of files
format:
	MSG_GEN_CLUSTER_REPORT ftime ttime
return:
	MSG_OK filename base64_str1 base64_str2 ... base64_strn
or
	MSG_FAIL
*/
#define MSG_GEN_CLUSTER_REPORT	"gen_cluster_report"

/*
description:
	get transition list
format:
	MSG_GET_PE_INPUTS FTIME TTIME
return:
	MSG_OK FILENAME1 TIME1 FILENAME2 TIME2 ... FILENAMEn TIMEn
or
	MSG_FAIL REASON
*/
#define MSG_GET_PE_INPUTS "get_pe_inputs"

/*
description:
	get transition summary
format:
	MSG_GET_PE_SUMMARY <live|PE_SERIES_NAME> <""|SEQUENCE>
return:
	MSG_OK TIME_STAMP
or
	MSG_FAIL REASON
*/
#define MSG_GET_PE_SUMMARY "get_pe_summary"

/*
description:
	generate specified transition graph
format:
	MSG_GEN_PE_GRAPH <live|TRANSITION_NUM>
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL REASON
*/
#define MSG_GEN_PE_GRAPH "gen_pe_graph"

/*
description:
	generate ptest information
format:
	MSG_GEN_PE_INFO <live|TRANSITION_NUM> <VERBOSITY|scores>
return:
	MSG_OK LINE1 LINE2 ... LINEn
or
	MSG_FAIL REASON
*/
#define MSG_GEN_PE_INFO "gen_pe_info"

/*************************EVENTS*********************************************/

/*
description:
	when the cib changed, client which registered this event will be 
	notified with this event message
format:
	EVT_CIB_CHANGED
*/
#define EVT_CIB_CHANGED		"evt:cib_changed"

/*
description:
	when the management daemon losts connection with heartbeat, client 
	which registered this event will be notified with this event message
format:
	EVT_DISCONNECTED
*/
#define EVT_DISCONNECTED	"evt:disconnected"

#define EVT_TEST		"evt:test"

/*************************FUNTIONS*******************************************/
/*
mgmt_set_mem_funcs:
	set user own memory functions, like malloc/realloc/free
 	for linux-ha 2
parameters:
	the three memory functions
return:
	none
*/
typedef void* 	(*malloc_t)(size_t size);
typedef void* 	(*realloc_t)(void* oldval, size_t newsize);
typedef void 	(*free_t)(void *ptr);
extern void	mgmt_set_mem_funcs(malloc_t m, realloc_t r, free_t f);
extern void* 	mgmt_malloc(size_t size);
extern void* 	mgmt_realloc(void* oldval, size_t newsize);
extern void 	mgmt_free(void *ptr);

/*
mgmt_new_msg:
	create a new message
parameters:
	type: should be the micro of MSG_XXX listed above
	... : the parameters listed above
return:
	a string as result, the format is described above
*/
extern char*	mgmt_new_msg(const char* type, ...);

/*
mgmt_msg_append:
	append a new parameter to an existing message
	the memory of the msg will be realloced.
parameters:
	msg: the original message
	append: the parameter to be appended
return:
	the new message
example:
	msg = mgmt_msg_append(msg, "new_param");
*/
extern char*	mgmt_msg_append(char* msg, const char* append);

/*
mgmt_del_msg:
	free a message
parameters:
	msg: the message to be free
return:
*/
extern void	mgmt_del_msg(char* msg);

/*
mgmt_result_ok:
	return whether the result is ok
parameters:
	msg: the message for determining
return:
	1: the result message is ok
	0: the result message is fail
*/
extern int	mgmt_result_ok(char* msg);

/*
mgmt_msg_args:
	parse the message to string arry
parameters:
	msg: the message to be parsed
	num: return the number of parameters
		(include type of message if the message has one)
return:
	the string arry, we should use mgmt_del_args() to free it
example:
	int i,num;
	char**	args = mgmt_msg_args(msg, &num);
	for(i=0; i<num; i++) {
		printf("%s\n",args[i]);
	}
	mgmt_del_args(args);
*/
extern char**	mgmt_msg_args(const char* msg, int* num);
extern void	mgmt_del_args(char** args);

#define	STRLEN_CONST(conststr)  ((size_t)((sizeof(conststr)/sizeof(char))-1))
#define	STRNCMP_CONST(varstr, conststr) strncmp((varstr), conststr, STRLEN_CONST(conststr)+1)

#define	MAX_MSGLEN	(256*1024)
#define	MAX_STRLEN	(64*1024)

#define INIT_SIZE	1024
#define INC_SIZE	512

#endif /* __MGMT_COMMON_H */
