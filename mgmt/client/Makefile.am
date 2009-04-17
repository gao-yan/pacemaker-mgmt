#
# heartbeat: Linux-HA heartbeat code
#
# Copyright (C) 2001 Michael Moerz
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


halibdir		= $(libdir)/@HB_PKG@
guilibdir              = @HA_DATADIR@/heartbeat-gui
guilib_SCRIPTS         = haclient.py mgmtcmd.py
guilib_DATA            = ha.png login.png logout.png exit.png \
			  standby-node.png active-node.png add-resource.png remove-resource.png \
			  start-resource.png stop-resource.png master-resource.png slave-resource.png \
			  default-resource.png up-resource.png down-resource.png cleanup-resource.png \
			  dirty-stopped.png failed.png running.png stopped.png starting.png stopping.png \
			  nodes.png node.png administration.png record-pending.png \
			  manage-resource.png unmanage-resource.png

desktopdir		= $(datadir)/applications
desktop_DATA		= crm_gui.desktop

INCLUDES 	      	= -I$(top_builddir)/include  -I$(top_srcdir)/include \
			  -I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha \
			  -I$(top_builddir)/libltdl -I$(top_srcdir)/libltdl

MGMT_DIR		= mgmt

halib_PROGRAMS 		= mgmtdtest
mgmtdtest_SOURCES  	= mgmtdtest.c
mgmtdtest_LDADD 	= $(top_builddir)/lib/$(MGMT_DIR)/libhbmgmtclient.la \
			  $(top_builddir)/lib/$(MGMT_DIR)/libhbmgmttls.la \
			  $(top_builddir)/lib/$(MGMT_DIR)/libhbmgmtcommon.la
mgmtdtest_LDFLAGS 	= $(GNUTLSLIBS)

EXTRA_DIST		= $(guilib_DATA)

