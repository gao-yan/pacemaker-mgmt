#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_NET_SNMP_NET_SNMP_CONFIG_H
#	define	USE_NET_SNMP
#else
#	define	USE_UCD_SNMP
#endif

#ifdef USE_NET_SNMP
#	include <net-snmp/net-snmp-config.h>
#	include <net-snmp/net-snmp-includes.h>
#	include <net-snmp/agent/net-snmp-agent-includes.h>
#	define	INIT_AGENT()	init_master_agent()
#else
#	include <ucd-snmp/ucd-snmp-config.h>
#	include <ucd-snmp/ucd-snmp-includes.h>
#	include <ucd-snmp/ucd-snmp-agent-includes.h>
#       ifndef NETSNMP_DS_APPLICATION_ID
#		define NETSNMP_DS_APPLICATION_ID	DS_APPLICATION_ID
#	endif
#	ifndef NETSNMP_DS_AGENT_ROLE
#		define NETSNMP_DS_AGENT_ROLE	DS_AGENT_ROLE
#	endif
#	define netsnmp_ds_set_boolean	ds_set_boolean
#	define	INIT_AGENT()	init_master_agent(161, NULL, NULL)
#endif

#include <signal.h>

static int keep_running;

static RETSIGTYPE stop_server(int a);

static RETSIGTYPE
stop_server(int a)
{
	keep_running = 0;
}

/*
 * As of this writing, this code does not compile correctly on
 * ucdsnmp 4.2.5-51 on SuSE Linux 8.1
 *
 * There are a few undefined symbolx I can't seem to find anywhere...
 *	hosts_ctl, and deny_severity.
 *
 * Close, but no cigar ;-)
 *
 */
int
main(int argc, char **argv)
{
	/* Change this if you want to be a SNMP master agent */
	int agentx_subagent=1;

	/* Print log errors to stderr */
	snmp_enable_stderrlog();

	/* We're an agentx subagent? */
	if (agentx_subagent) {
		/* Make us an agentx client. */
		netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID
		,	NETSNMP_DS_AGENT_ROLE, 1);
	}

	/* Initialize the agent library */
	init_agent("hasubagent");

	/* Initialize mib code here */

	/* mib code: init_nstAgentSubagentObject from nstAgentSubagentObject.C */
	// init_nstAgentSubagentObject();  

	/* hasubagent will be used to read hasubagent.conf files. */
	init_snmp("hasubagent");

	/* If we're going to be a snmp master agent, initial the ports */
	if (!agentx_subagent) {
		/* Open the port to listen on (defaults to udp:161) */
		INIT_AGENT();
	}

	/* In case we receive a request to stop (kill -TERM or kill -INT) */
	keep_running = 1;
	signal(SIGTERM, stop_server);
	signal(SIGINT, stop_server);

	/* You're main loop here... */
	while(keep_running) {
		/* If you use select(), see snmp_select_info() in snmp_api(3) */
		/*     --- OR ---  */
		agent_check_and_process(1); /* 0 == don't block */
	}

	/* At shutdown time */
	snmp_shutdown("hasubagent");
	return 0;
}

