#
#  Author: Sun Jiang Dong <sunjd@cn.ibm.com>
#  Copyright (c) 2005 International Business Machines
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
MAINTAINERCLEANFILES = Makefile.in

INCLUDES        = -I$(top_builddir)/include  -I$(top_srcdir)/include     \
                  -I$(top_builddir)/libltdl  -I$(top_srcdir)/libltdl     \
		  -I$(top_builddir)/linux-ha -I$(top_srcdir)/linux-ha    \
		  -I$(top_builddir)          -I$(top_srcdir)

halibdir	=  $(libdir)/@HB_PKG@

COMMONLIBS	=  -lplumb $(GLIBLIB)
noinst_HEADERS	=  mgmt_internal.h
EXTRA_DIST	=  mgmtd.pam mgmtd.pam.common
LRM_DIR		= lrm

pamdir 		= $(sysconfdir)/pam.d
if USE_PAM_COMMON
pam_DATA	= mgmtd.pam.common
else
pam_DATA	= mgmtd.pam
endif

install-data-hook:
		mv $(DESTDIR)$(pamdir)/$(pam_DATA) $(DESTDIR)$(pamdir)/hbmgmtd


halib_PROGRAMS 	=  mgmtd
mgmtd_SOURCES 	=  mgmtd.c
mgmtd_LDFLAGS	= -lpam
mgmtd_LDADD 	=  $(top_builddir)/lib/mgmt/libhbmgmtclient.la \
		   $(top_builddir)/lib/mgmt/libhbmgmttls.la \
		   libhbmgmt.la \
		   $(top_builddir)/lib/mgmt/libhbmgmtcommon.la \
		   $(COMMONLIBS)

if HAVE_PACEMAKER_LRMD
mgmtd_LDADD 	+= -llrmd
else
mgmtd_LDADD 	+= -llrm
endif

lib_LTLIBRARIES = libhbmgmt.la
libhbmgmt_la_SOURCES = mgmt_lib.c mgmt_crm.c
if HAVE_PACEMAKER_LRMD
libhbmgmt_la_SOURCES += mgmt_pacemaker_lrm.c
else
libhbmgmt_la_SOURCES += mgmt_lrm.c
endif


if BUILD_HEARTBEAT_SUPPORT
libhbmgmt_la_SOURCES += mgmt_hb.c
endif
libhbmgmt_la_CFLAGS = $(INCLUDES)
libhbmgmt_la_LDFLAGS = $(GNUTLSLIBS)
libhbmgmt_la_LIBADD = $(top_builddir)/lib/mgmt/libhbmgmttls.la 			\
		  	-lcib -lcrmcommon -lpe_status -lcrmcluster	\
			$(COMMONLIBS) $(CLUSTERLIBS) $(CURSESLIBS)
