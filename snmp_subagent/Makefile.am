# Linux-HA: SNMP Subagent
# 
# Copyright (C) 2002 Yixiong Zou (yixiong.zou@intel.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

MAINTAINERCLEANFILES    = Makefile.in

hbagent_srces  = snmp-config-resolve.h	\
	hbagent.h			\
	hbagent.c			\
	hbagentv2.h			\
	hbagentv2.c			\
	LHANodeTable.h			\
	LHANodeTable_columns.h		\
	LHANodeTable_enums.h		\
	LHANodeTable.c			\
	LHAClusterInfo.h		\
	LHAClusterInfo.c		\
	LHAIFStatusTable.h		\
	LHAIFStatusTable_enums.h	\
	LHAIFStatusTable_columns.h	\
	LHAIFStatusTable.c		\
	LHAMembershipTable_columns.h	\
	LHAMembershipTable_enums.h	\
	LHAMembershipTable.h		\
	LHAMembershipTable.c		\
	LHAHeartbeatConfigInfo.c	\
	LHAHeartbeatConfigInfo.h	\
	LHAResourceGroupTable_columns.h	\
	LHAResourceGroupTable_enums.h	\
	LHAResourceGroupTable.h		\
	LHAResourceGroupTable.c		\
	LHAResourceTable_columns.h \
	LHAResourceTable_enums.h \
	LHAResourceTable.h		\
	LHAResourceTable.c		\
	LHAResourceStatusUpdate.h \
	LHAResourceStatusUpdate.c 

test_scrs	=	SNMPAgentSanityCheck


mibsdir			= @MIBS_DIR@
mibs_DATA		= LINUX-HA-MIB.txt
DIST_LIST		= SNMPAgentSanityCheck.in $(mibs_DATA)

EXTRA_DIST		= $(DIST_LIST)

docdir			= $(datadir)/doc/packages/@PKG_NAME@
doc_DATA		= README.hbagent README.hbagentv2

INCLUDES                = -I$(top_builddir)/include -I$(top_srcdir)/include \
			-I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

halibdir		= $(libdir)/@HB_PKG@

# binary programs
halib_PROGRAMS		= hbagent 

hbagent_SOURCES		= $(hbagent_srces)

hbagent_LDADD	 	= \
			-lplumb -lcrmcommon -lcib -lpe_status \
			$(CLUSTERLIBS) $(CURSESLIBS) $(GLIBLIB)

if !BUILD_HEARTBEAT_SUPPORT
hbagent_LDADD		+= -lcrmcluster
endif
hbagent_LDFLAGS		= @SNMPAGENTLIB@ 

# test cases
testdir			= $(HA_LIBHBDIR)
test_SCRIPTS		= $(test_scrs)

hadir                   = $(sysconfdir)/ha.d

AM_CFLAGS               = @CFLAGS@
