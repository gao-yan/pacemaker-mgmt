/*
 * Copyright (C) 2012 Gao,Yan <ygao@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <pygui_internal.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <stdbool.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/cl_syslog.h>

#include "mgmt_internal.h"
#include <crm/lrmd.h>

static char* on_rsc_class(char* argv[], int argc);
static char* on_rsc_type(char* argv[], int argc);
static char* on_rsc_provider(char* argv[], int argc);
static char* on_rsc_metadata(char* argv[], int argc);
static char* on_lrm_op_rc2str(char* argv[], int argc);


lrmd_t *lrmd_conn = NULL;
int init_lrm(void);
void final_lrm(void);

int
init_lrm(void)
{
	int rc = 0;
	int i = 0; 
	int max_try = 5;

	lrmd_conn = lrmd_api_new();
	for (i = 0; i < max_try; i++) {
        rc = lrmd_conn->cmds->connect(lrmd_conn, "mgmtd", NULL);
		if (rc == 0) {
			break;
		}
		mgmt_log(LOG_NOTICE,"connect to lrmd: %d, rc=%d", i, rc);
		sleep(1);
	}
	if (rc != 0) {
		mgmt_log(LOG_WARNING,"connect to lrmd failed");
        lrmd_api_delete(lrmd_conn);
		lrmd_conn = NULL;
		return -1;
	}

	reg_msg(MSG_RSC_CLASSES, on_rsc_class);
	reg_msg(MSG_RSC_TYPES, on_rsc_type);
	reg_msg(MSG_RSC_PROVIDERS, on_rsc_provider);
	reg_msg(MSG_RSC_METADATA, on_rsc_metadata);
	reg_msg(MSG_LRM_OP_RC2STR, on_lrm_op_rc2str);
	return 0;
}	


void
final_lrm(void)
{
	if (lrmd_conn != NULL) {
        lrmd_conn->cmds->disconnect(lrmd_conn);
        lrmd_api_delete(lrmd_conn);
		lrmd_conn = NULL;
	}
}

char* 
on_rsc_class(char* argv[], int argc)
{
    int rc = 0;
    lrmd_list_t *list = NULL;
    lrmd_list_t *iter = NULL;
	char* ret = strdup(MSG_OK);

    rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);

    if (rc > 0) {
        for (iter = list; iter != NULL; iter = iter->next) {
            ret = mgmt_msg_append(ret, iter->val);
        }
        lrmd_list_freeall(list);

    } else {
        mgmt_log(LOG_ERR, "No resource classes found");
    }

	return ret;
}

char* 
on_rsc_type(char* argv[], int argc)
{
    int rc = 0;
    lrmd_list_t *list = NULL;
    lrmd_list_t *iter = NULL;
	
    char* ret = NULL;

    ARGC_CHECK(2)
	
    ret = strdup(MSG_OK);

    rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, argv[1], NULL);

    if (rc > 0) {
        for (iter = list; iter != NULL; iter = iter->next) {
		    ret = mgmt_msg_append(ret, iter->val);
        }
        lrmd_list_freeall(list);

    } else {
        mgmt_log(LOG_NOTICE, "No %s resource types found", argv[1]);
    }

	return ret;
}

char* 
on_rsc_provider(char* argv[], int argc)
{
    int rc = 0;
    lrmd_list_t *list = NULL;
    lrmd_list_t *iter = NULL;

    char* ret = strdup(MSG_OK);

    rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, argv[2], &list);

    if (rc > 0) {
        for (iter = list; iter != NULL; iter = iter->next) {
		    ret = mgmt_msg_append(ret, iter->val);
        }
        lrmd_list_freeall(list);

    } else {
        mgmt_log(LOG_ERR, "No %s providers found for %s", argv[1], argv[2]);
    }

	return ret;
}
char*
on_rsc_metadata(char* argv[], int argc)
{
    int rc = 0;
    char *output = NULL;
    char* ret = NULL;

    rc = lrmd_conn->cmds->get_metadata(lrmd_conn, argv[1], argv[3], argv[2], &output, 0);
    if (rc == 0) {
        ret = strdup(MSG_OK);
        ret = mgmt_msg_append(ret, output);
        free(output);
        return ret;
    }

	return strdup(MSG_FAIL);
}

char*
on_lrm_op_rc2str(char* argv[], int argc)
{
	int rc = 0;
	char* ret = strdup(MSG_OK);

	rc = atoi(argv[1]);
#if !HAVE_DECL_SERVICES_OCF_EXITCODE_STR
	ret = mgmt_msg_append(ret, lrmd_event_rc2str(rc));
#else
	ret = mgmt_msg_append(ret, services_ocf_exitcode_str(rc));
#endif
	return ret;
}
