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

mibsdir			= @MIBS_DIR@
mibs_DATA		= LINUX-HA-MIB.mib

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include

COMMONLIBS              = $(top_builddir)/lib/clplumbing/libplumb.la    \
			$(GLIBLIB)

halibdir		= $(libdir)/@HB_PKG@

NET_SNMP_CONFIG		= @NET_SNMP_CONFIG@

# binary programs
halib_PROGRAMS		= hasubagent

hasubagent_SOURCES	= hasubagent.c

hasubagent_LDADD	= $(COMMONLIBS) @HASUBAGENT_LDADD_EXTRA@
hasubagent_LDFLAGS	= @HASUBAGENT_LDFLAGS@
